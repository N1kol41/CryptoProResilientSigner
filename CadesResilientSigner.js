/**
 * @file CadesResilientSigner.js
 * Отказоустойчивое пакетное подписание через КриптоПро ЭЦП в Internet Explorer.
 * Поддерживает:
 *  - Автоматическое возобновление после падения вкладки/браузера (LocalStorage Checkpoints)
 *  - Изоляцию памяти: пакетная обработка чанками с вызовом CollectGarbage()
 *  - Сторожевой таймер (Watchdog) против зависания модального окна PIN-кода
 *  - Корректную очистку COM-хэндлов ActiveX
 */

(function (window) {
    'use strict';

    var STORAGE_KEY_PREFIX = 'CP_BATCH_';
    var CADES_BES = 1;
    var CADESCOM_BASE64_TO_BINARY = 1;
    var CAPICOM_CURRENT_USER_STORE = 2;
    var CAPICOM_MY_STORE = "My";
    var CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
    var CERT_FIND_SHA1_HASH = 0;

    function ResilientSigner(options) {
        this.batchId = options.batchId || 'batch_' + new Date().getTime();
        this.certThumbprint = options.certThumbprint;
        this.chunkSize = options.chunkSize || 10; // очистка памяти каждые N документов
        this.docTimeoutMs = options.docTimeoutMs || 35000; // таймаут на 1 документ (PIN-код)
        this.onProgress = options.onProgress || function() {};
        this.onError = options.onError || function() {};
        this.onComplete = options.onComplete || function() {};
        
        this.state = this.loadCheckpoint() || {
            batchId: this.batchId,
            documents: options.documents || [],
            currentIndex: 0,
            signedCount: 0,
            failedCount: 0,
            status: 'INITIALIZED',
            lastUpdated: new Date().getTime()
        };
    }

    /**
     * Загрузка контрольной точки из LocalStorage
     */
    ResilientSigner.prototype.loadCheckpoint = function () {
        try {
            var raw = window.localStorage.getItem(STORAGE_KEY_PREFIX + this.batchId);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    };

    /**
     * Сохранение атомарного снимка состояния
     */
    ResilientSigner.prototype.saveCheckpoint = function () {
        try {
            this.state.lastUpdated = new Date().getTime();
            window.localStorage.setItem(
                STORAGE_KEY_PREFIX + this.batchId, 
                JSON.stringify(this.state)
            );
        } catch (e) {
            // LocalStorage квота или приватный режим
        }
    };

    /**
     * Очистка журнала после успешного завершения всего пакета
     */
    ResilientSigner.prototype.clearCheckpoint = function () {
        try {
            window.localStorage.removeItem(STORAGE_KEY_PREFIX + this.batchId);
        } catch (e) {}
    };

    /**
     * Проверка: есть ли незавершенный пакет после падения IE
     */
    ResilientSigner.hasPendingBatch = function (batchId) {
        try {
            var raw = window.localStorage.getItem(STORAGE_KEY_PREFIX + batchId);
            if (!raw) return false;
            var data = JSON.parse(raw);
            return data.status === 'IN_PROGRESS' && data.currentIndex < data.documents.length;
        } catch (e) {
            return false;
        }
    };

    /**
     * Поиск сертификата в хранилище Windows MY
     */
    ResilientSigner.prototype.getCertificate = function (thumbprint) {
        var oStore = null;
        var oCerts = null;
        try {
            oStore = new ActiveXObject("CAdESCOM.Store");
            oStore.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
            
            var cleanThumb = thumbprint.replace(/\s+/g, '').toUpperCase();
            oCerts = oStore.Certificates.Find(CERT_FIND_SHA1_HASH, cleanThumb);
            
            if (oCerts.Count === 0) {
                throw new Error("Сертификат с отпечатком " + cleanThumb + " не найден в хранилище 'Личные'");
            }
            return oCerts.Item(1);
        } finally {
            if (oStore) {
                try { oStore.Close(); } catch (e) {}
            }
            oStore = null;
            oCerts = null;
        }
    };

    /**
     * Низкоуровневое подписание одного документа с изоляцией COM и сбором мусора
     */
    ResilientSigner.prototype.signSingleDocument = function (cert, docItem, callback) {
        var self = this;
        var oSigner = null;
        var oSignedData = null;
        var isDone = false;

        // Watchdog таймер на случай зависания диалога cpui.dll
        var watchdogTimer = setTimeout(function () {
            if (!isDone) {
                isDone = true;
                self.forceCleanupCOM(oSigner, oSignedData);
                callback(new Error("Превышен таймаут подписания (" + (self.docTimeoutMs / 1000) + " сек). Возможно, зависло окно ввода PIN-кода."));
            }
        }, this.docTimeoutMs);

        // Запуск через setTimeout дает IE возможность обработать очередь сообщений Windows
        setTimeout(function () {
            try {
                oSigner = new ActiveXObject("CAdESCOM.CPSigner");
                oSigner.Certificate = cert;
                oSigner.CheckCertificate = true;

                oSignedData = new ActiveXObject("CAdESCOM.CadesSignedData");
                // Base64 содержимое документа
                oSignedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
                oSignedData.Content = docItem.base64Content;

                // Формирование отсоединенной подписи (CADES_BES)
                var signature = oSignedData.SignCades(oSigner, CADES_BES, true);

                if (!isDone) {
                    isDone = true;
                    clearTimeout(watchdogTimer);
                    self.forceCleanupCOM(oSigner, oSignedData);
                    callback(null, signature);
                }
            } catch (err) {
                if (!isDone) {
                    isDone = true;
                    clearTimeout(watchdogTimer);
                    var hexCode = "0x" + ((err.number >>> 0).toString(16).toUpperCase());
                    self.forceCleanupCOM(oSigner, oSignedData);
                    err.hexCode = hexCode;
                    callback(err);
                }
            }
        }, 10);
    };

    /**
     * Принудительное обнуление COM-ссылок и вызов JScript Garbage Collector
     */
    ResilientSigner.prototype.forceCleanupCOM = function (oSigner, oSignedData) {
        try { oSigner = null; } catch(e) {}
        try { oSignedData = null; } catch(e) {}
        
        // Специфично для Internet Explorer (JScript)
        if (typeof window.CollectGarbage === "function") {
            window.CollectGarbage();
        }
    };

    /**
     * Главный управляющий цикл пакета
     */
    ResilientSigner.prototype.start = function () {
        var self = this;
        var cert = null;

        try {
            cert = this.getCertificate(this.certThumbprint);
        } catch (e) {
            this.onError(e);
            return;
        }

        this.state.status = 'IN_PROGRESS';
        this.saveCheckpoint();

        function processNext() {
            if (self.state.currentIndex >= self.state.documents.length) {
                self.state.status = 'COMPLETED';
                self.saveCheckpoint();
                self.clearCheckpoint();
                self.onComplete(self.state);
                return;
            }

            var doc = self.state.documents[self.state.currentIndex];
            doc.status = 'SIGNING';
            self.saveCheckpoint();
            self.onProgress(self.state.currentIndex, self.state.documents.length, doc);

            self.signSingleDocument(cert, doc, function (err, signature) {
                if (err) {
                    doc.retryCount = (doc.retryCount || 0) + 1;
                    
                    // Ошибка 0x800706BA (Сервер RPC недоступен) - падение службы/процесса
                    if (err.hexCode === "0x800706BA" && doc.retryCount <= 2) {
                        doc.status = 'RETRYING';
                        self.saveCheckpoint();
                        // Пауза 2 сек для перезапуска криптопровайдера и повтор
                        setTimeout(function () {
                            try { cert = self.getCertificate(self.certThumbprint); } catch(ex) {}
                            processNext();
                        }, 2000);
                        return;
                    }

                    doc.status = 'FAILED';
                    doc.error = err.message + " (" + (err.hexCode || 'N/A') + ")";
                    self.state.failedCount++;
                } else {
                    doc.status = 'SIGNED';
                    doc.signature = signature;
                    self.state.signedCount++;
                }

                self.state.currentIndex++;
                self.saveCheckpoint();

                // Пакетирование: очистка каждые N документов (для предотвращения 32-bit OOM)
                if (self.state.currentIndex % self.chunkSize === 0) {
                    if (typeof window.CollectGarbage === "function") {
                        window.CollectGarbage();
                    }
                    // Микропауза для разгрузки UI-потока IE
                    setTimeout(processNext, 250);
                } else {
                    setTimeout(processNext, 20);
                }
            });
        }

        processNext();
    };

    window.ResilientSigner = ResilientSigner;
})(window);
