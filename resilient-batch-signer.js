/**
 * @file resilient-batch-signer.js
 * @description Отказоустойчивый модуль пакетного подписания документов через КриптоПро ЭЦП в Internet Explorer / Edge IE Mode.
 * 
 * Особенности:
 * 1. Проверка зависаний процесса (Watchdog): фоновый монитор замеряет время выполнения операции.
 *    При превышении таймаута (завис диалог ввода PIN, драйвер или COM) производит сброс и авто-перезапуск.
 * 2. Защита от «зомби-откликов»: токен поколения операции (generationId) отсекает запоздалые ответы.
 * 3. Атомарные контрольные точки: журнал в window.localStorage сохраняет прогресс.
 *    При F5, закрытии вкладки или перезапуске браузера подписание продолжается с прерванного документа.
 * 4. Управление 32-битной памятью кучи: принудительное зануление COM-указателей и вызов window.CollectGarbage().
 * 5. Совместимость: 100% чистый JavaScript ES5, совместимый с IE9-IE11 и современными браузерами.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ResilientBatchSigner = factory();
  }
})(typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  var CADES_BES = 1;
  var CADESCOM_BASE64_TO_BINARY = 1;
  var CAPICOM_CURRENT_USER_STORE = 2;
  var CAPICOM_MY_STORE = "My";
  var CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
  var CERT_FIND_SHA1_HASH = 0;

  /**
   * Конструктор ResilientBatchSigner
   * @param {Object} options Параметры конфигурации
   * @param {Array} options.documents Массив объектов документов: [{ id, name, base64, size }]
   * @param {string} options.certThumbprint Отпечаток SHA-1 сертификата
   * @param {string} [options.storageKey] Ключ LocalStorage для контрольных точек
   * @param {number} [options.timeoutSec] Таймаут зависания одного документа в секундах (по умолч. 15)
   * @param {number} [options.chunkSize] Количество документов для принудительного вызова CollectGarbage (по умолч. 2)
   * @param {number} [options.rpcRetryDelayMs] Пауза перед перезапуском при ошибке 0x800706BA (по умолч. 2000 мс)
   * @param {Function} [options.onProgress] Коллбек прогресса (currentIndex, total, docItem)
   * @param {Function} [options.onDocSigned] Коллбек успешного подписания (docItem, signature)
   * @param {Function} [options.onDocError] Коллбек ошибки (docItem, error)
   * @param {Function} [options.onHangDetected] Коллбек обнаружения зависания (docItem, elapsedSec)
   * @param {Function} [options.onRestart] Коллбек авто-перезапуска (docItem, retriesCount)
   * @param {Function} [options.onComplete] Коллбек завершения всего пакета (summary)
   * @param {Function} [options.onStatusChange] Коллбек смены статуса (statusString, details)
   * @param {Function} [options.onLog] Коллбек журнала событий (message, type)
   */
  function ResilientBatchSigner(options) {
    if (!options) options = {};

    this.documents = options.documents ? this._cloneDocs(options.documents) : [];
    this.certThumbprint = options.certThumbprint || '';
    this.storageKey = options.storageKey || 'CP_RESILIENT_BATCH_STATE';
    this.timeoutSec = options.timeoutSec || 15;
    this.chunkSize = options.chunkSize || 2;
    this.rpcRetryDelayMs = options.rpcRetryDelayMs || 2000;

    // Коллбеки
    this.onProgress = options.onProgress || function () {};
    this.onDocSigned = options.onDocSigned || function () {};
    this.onDocError = options.onDocError || function () {};
    this.onHangDetected = options.onHangDetected || function () {};
    this.onRestart = options.onRestart || function () {};
    this.onComplete = options.onComplete || function () {};
    this.onStatusChange = options.onStatusChange || function () {};
    this.onLog = options.onLog || function () {};

    // Внутреннее состояние
    this.currentIndex = 0;
    this.isRunning = false;
    this.isPaused = false;
    this.isCurrentlyHanging = false; // для имитации/тестирования зависания
    this.currentDocStartTime = 0;
    this.operationGenerationId = 1;
    this.restartCount = 0;
    this.watchdogIntervalId = null;

    // Проверяем наличие контрольной точки из предыдущей сессии
    this._restoreCheckpointIfAvailable();

    // Запускаем постоянный фоновый сторожевой монитор зависаний
    this._startWatchdogMonitor();
  }

  // Клонирование документов с инициализацией полей статуса
  ResilientBatchSigner.prototype._cloneDocs = function (docs) {
    var list = [];
    for (var i = 0; i < docs.length; i++) {
      var d = docs[i];
      list.push({
        id: d.id || 'DOC-' + (i + 1),
        name: d.name || 'Документ #' + (i + 1),
        base64: d.base64 || 'PHJvb3Q+VGVzdCBkYXRhPC9yb290Pg==',
        size: d.size || '100 КБ',
        status: d.status || 'pending',
        signature: d.signature || null,
        retries: d.retries || 0,
        error: d.error || null
      });
    }
    return list;
  };

  /**
   * Загрузка контрольной точки из LocalStorage
   */
  ResilientBatchSigner.prototype.loadCheckpoint = function () {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        var raw = window.localStorage.getItem(this.storageKey);
        return raw ? JSON.parse(raw) : null;
      }
    } catch (e) {}
    return null;
  };

  /**
   * Сохранение контрольной точки
   */
  ResilientBatchSigner.prototype.saveCheckpoint = function (idx) {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.setItem(this.storageKey, JSON.stringify({
          currentIndex: idx,
          total: this.documents.length,
          savedAt: new Date().getTime()
        }));
      }
    } catch (e) {}
  };

  /**
   * Очистка контрольной точки
   */
  ResilientBatchSigner.prototype.clearCheckpoint = function () {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.removeItem(this.storageKey);
      }
    } catch (e) {}
  };

  /**
   * Восстановление состояния при открытии страницы
   */
  ResilientBatchSigner.prototype._restoreCheckpointIfAvailable = function () {
    var saved = this.loadCheckpoint();
    if (saved && saved.currentIndex > 0 && saved.currentIndex < this.documents.length) {
      this.currentIndex = saved.currentIndex;
      for (var i = 0; i < this.currentIndex; i++) {
        this.documents[i].status = 'signed';
      }
      this.onLog('ОБНАРУЖЕНА НЕЗАВЕРШЕННАЯ СЕССИЯ: ранее подписано ' + saved.currentIndex + ' из ' + this.documents.length + ' файлов.', 'warn');
      this.onStatusChange('RESTORED_PENDING', { index: this.currentIndex, total: this.documents.length });
    }
  };

  /**
   * Поиск сертификата в хранилище Windows "Личные" (MY)
   */
  ResilientBatchSigner.prototype.getCertificate = function (thumbprint) {
    if (typeof ActiveXObject === 'undefined') {
      return { mock: true, thumbprint: thumbprint }; // для сред без IE ActiveX
    }

    var oStore = null;
    var oCerts = null;
    try {
      oStore = new ActiveXObject("CAdESCOM.Store");
      oStore.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
      var clean = thumbprint.replace(/\s+/g, '').toUpperCase();
      oCerts = oStore.Certificates.Find(CERT_FIND_SHA1_HASH, clean);
      if (oCerts.Count === 0) {
        throw new Error("Сертификат с отпечатком " + clean + " не найден в хранилище 'Личные'");
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
   * Принудительное освобождение COM памяти
   */
  ResilientBatchSigner.prototype.collectGarbageSafe = function () {
    if (typeof window !== 'undefined' && typeof window.CollectGarbage === 'function') {
      window.CollectGarbage();
    }
  };

  /**
   * Запуск фонового сторожевого таймера (Watchdog Monitor)
   */
  ResilientBatchSigner.prototype._startWatchdogMonitor = function () {
    var self = this;
    if (this.watchdogIntervalId) clearInterval(this.watchdogIntervalId);

    this.watchdogIntervalId = setInterval(function () {
      self._checkProcessHangTick();
    }, 500);
  };

  /**
   * Периодический шаг проверки зависаний
   */
  ResilientBatchSigner.prototype._checkProcessHangTick = function () {
    if (!this.isRunning || this.currentIndex >= this.documents.length) return;

    var now = new Date().getTime();
    var elapsedMs = now - this.currentDocStartTime;
    var elapsedSec = elapsedMs / 1000;

    // ПРОВЕРКА: превышен ли лимит ожидания?
    if (elapsedSec >= this.timeoutSec) {
      this._triggerHangRecovery(elapsedSec);
    }
  };

  /**
   * Процедура автоматического перезапуска при зависании
   */
  ResilientBatchSigner.prototype._triggerHangRecovery = function (elapsedSec) {
    var doc = this.documents[this.currentIndex];
    this.isCurrentlyHanging = false;
    this.restartCount++;

    this.onLog('🚨 СТОРОЖЕВОЙ ТАЙМЕР: ОБНАРУЖЕНО ЗАВИСАНИЕ ПРОЦЕССА! Документ #' + (this.currentIndex + 1) + ' (' + doc.name + ') не отвечает ' + elapsedSec.toFixed(1) + ' сек.', 'err');

    // 1. Аннулируем токен поколения текущей операции
    this.operationGenerationId++;

    // 2. Освобождаем зависшие дескрипторы COM
    this.collectGarbageSafe();

    // 3. Отмечаем документ как retrying
    doc.retries = (doc.retries || 0) + 1;
    doc.status = 'retrying';

    this.onHangDetected(doc, elapsedSec);
    this.onRestart(doc, doc.retries);
    this.onStatusChange('HANG_RECOVERY', { doc: doc, retries: doc.retries });

    // 4. АВТОМАТИЧЕСКИЙ ПЕРЕЗАПУСК ПОДПИСАНИЯ
    var self = this;
    setTimeout(function () {
      self.onLog('🔄 АВТО-ПЕРЕЗАПУСК: Повторный запуск подписания документа #' + (self.currentIndex + 1) + '...', 'succ');
      self.onStatusChange('RUNNING', { doc: doc });
      self._stepSigning();
    }, 1000);
  };

  /**
   * Старт или возобновление процесса пакетного подписания
   */
  ResilientBatchSigner.prototype.start = function () {
    if (this.isRunning) return;

    this.isRunning = true;
    this.isPaused = false;
    this.isCurrentlyHanging = false;
    this.onStatusChange('RUNNING', { index: this.currentIndex });
    this.onLog('Запуск процесса пакетного подписания со сторожевым контролем...', 'sys');

    this._stepSigning();
  };

  /**
   * Приостановка пакета
   */
  ResilientBatchSigner.prototype.pause = function () {
    this.isRunning = false;
    this.isPaused = true;
    this.isCurrentlyHanging = false;
    this.onStatusChange('PAUSED', { index: this.currentIndex });
    this.onLog('Пакет приостановлен оператором.', 'warn');
  };

  /**
   * Полный сброс состояния
   */
  ResilientBatchSigner.prototype.reset = function () {
    this.isRunning = false;
    this.isPaused = false;
    this.isCurrentlyHanging = false;
    this.currentIndex = 0;
    this.restartCount = 0;
    this.clearCheckpoint();

    for (var i = 0; i < this.documents.length; i++) {
      this.documents[i].status = 'pending';
      this.documents[i].retries = 0;
      this.documents[i].signature = null;
      this.documents[i].error = null;
    }

    this.onStatusChange('RESET', { total: this.documents.length });
    this.onLog('Состояние пакета и LocalStorage очищены.', 'sys');
  };

  /**
   * Имитация зависания (для проверки сторожевого таймера)
   */
  ResilientBatchSigner.prototype.simulateHang = function () {
    if (!this.isRunning) {
      this.start();
    }
    this.isCurrentlyHanging = true;
    this.onLog('🛑 ИМИТАЦИЯ ЗАВИСАНИЯ: Модальное окно ввода PIN / поток COM заблокирован!', 'err');
    this.onLog('Сторожевой таймер отсчитывает время до авто-перезапуска (лимит: ' + this.timeoutSec + ' сек)...', 'warn');
    this.onStatusChange('STALLED', { doc: this.documents[this.currentIndex] });
  };

  /**
   * Основной единичный шаг подписания документа
   */
  ResilientBatchSigner.prototype._stepSigning = function () {
    var self = this;
    if (!this.isRunning) return;

    // Проверка окончания пакета
    if (this.currentIndex >= this.documents.length) {
      this.isRunning = false;
      this.clearCheckpoint();
      this.onStatusChange('COMPLETED', { total: this.documents.length, restarts: this.restartCount });
      this.onLog('ВСЕ ДОКУМЕНТЫ УСПЕШНО ПОДПИСАНЫ! Контрольная точка очищена.', 'succ');
      this.onComplete({
        total: this.documents.length,
        restartCount: this.restartCount,
        documents: this.documents
      });
      return;
    }

    var doc = this.documents[this.currentIndex];
    doc.status = 'signing';
    this.currentDocStartTime = new Date().getTime(); // Засекаем время для Watchdog
    var opId = this.operationGenerationId;           // Запоминаем ID поколения

    this.onProgress(this.currentIndex, this.documents.length, doc);
    this.onLog('Подписание документа #' + (this.currentIndex + 1) + ': ' + doc.name + '...');

    // Запуск низкоуровневого вызова с защитой
    this._executeLowLevelSign(doc, function (err, signature) {
      // Защита от зомби-коллбека: если сторожевой таймер уже перезапустил операцию
      if (opId !== self.operationGenerationId) {
        self.onLog('Отброшен устаревший ответ от зависшей операции #' + opId, 'sys');
        return;
      }

      // Если искусственно включено зависание — ничего не делаем, ждем срабатывания Watchdog
      if (self.isCurrentlyHanging) {
        self.onLog('Операция заблокирована (эмуляция зависания окна PIN / COM)...', 'warn');
        return;
      }

      if (!self.isRunning) return;

      if (err) {
        doc.error = err.message || 'Ошибка COM';

        // При сбое RPC (0x800706BA) — автоматический повтор через rpcRetryDelayMs
        if (err.hexCode === '0x800706BA') {
          self.onLog('СБОЙ RPC (0x800706BA): падение процесса криптопровайдера. Перезапуск через ' + (self.rpcRetryDelayMs / 1000) + ' сек...', 'err');
          doc.status = 'retrying';
          doc.retries = (doc.retries || 0) + 1;
          setTimeout(function () {
            self._stepSigning();
          }, self.rpcRetryDelayMs);
          return;
        }

        // При сбое токена (0x80090016) — ставим на паузу до подключения
        if (err.hexCode === '0x80090016') {
          self.onLog('СБОЙ 0x80090016: Токен не найден в USB. Пакет приостановлен.', 'err');
          doc.status = 'retrying';
          self.pause();
          self.onDocError(doc, err);
          return;
        }

        doc.status = 'failed';
        self.onDocError(doc, err);
        self.onLog('Ошибка подписания документа ' + doc.name + ': ' + err.message, 'err');
        return;
      }

      // Успешно подписано
      doc.status = 'signed';
      doc.signature = signature;
      self.currentIndex++;
      self.saveCheckpoint(self.currentIndex);

      // Контроль памяти: зануление и вызов CollectGarbage каждые chunkSize документов
      if (self.currentIndex % self.chunkSize === 0) {
        self.collectGarbageSafe();
        self.onLog('Освобождение COM-ссылок и вызов CollectGarbage() (чанковая очистка)', 'sys');
      }

      self.onDocSigned(doc, signature);
      self.onProgress(self.currentIndex, self.documents.length, doc);
      self.onLog('Документ #' + self.currentIndex + ' успешно подписан. Контрольная точка сохранена.', 'succ');

      // Неблокирующий переход к следующему документу
      setTimeout(function () {
        self._stepSigning();
      }, 150);
    });
  };

  /**
   * Низкоуровневое подписание документа через CAdESCOM или имитатор
   */
  ResilientBatchSigner.prototype._executeLowLevelSign = function (doc, callback) {
    var self = this;

    // В среде Internet Explorer с активным ActiveX
    if (typeof ActiveXObject !== 'undefined') {
      var oSigner = null;
      var oSignedData = null;
      var oStore = null;

      setTimeout(function () {
        try {
          oStore = new ActiveXObject("CAdESCOM.Store");
          oStore.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
          var certs = oStore.Certificates.Find(CERT_FIND_SHA1_HASH, self.certThumbprint.replace(/\s+/g, ''));
          if (certs.Count === 0) throw new Error("Сертификат не найден в Личных");

          oSigner = new ActiveXObject("CAdESCOM.CPSigner");
          oSigner.Certificate = certs.Item(1);

          oSignedData = new ActiveXObject("CAdESCOM.CadesSignedData");
          oSignedData.ContentEncoding = CADESCOM_BASE64_TO_BINARY;
          oSignedData.Content = doc.base64;

          var signature = oSignedData.SignCades(oSigner, CADES_BES, true);

          // Очистка COM
          oSigner = null;
          oSignedData = null;
          if (oStore) { try { oStore.Close(); } catch (e) {} }
          oStore = null;
          self.collectGarbageSafe();

          callback(null, signature);
        } catch (e) {
          oSigner = null;
          oSignedData = null;
          if (oStore) { try { oStore.Close(); } catch (ex) {} }
          oStore = null;
          self.collectGarbageSafe();

          var hex = "0x" + ((e.number >>> 0).toString(16).toUpperCase());
          e.hexCode = hex;
          callback(e);
        }
      }, 50);
    } else {
      // Имитатор для сред без ActiveX (для тестирования логики в браузере)
      setTimeout(function () {
        var fakeSig = 'CADES_BES_' + Math.random().toString(36).substring(2, 12).toUpperCase();
        callback(null, fakeSig);
      }, 500);
    }
  };

  /**
   * Получение текущей статистики
   */
  ResilientBatchSigner.prototype.getStatus = function () {
    var signed = 0;
    var failed = 0;
    for (var i = 0; i < this.documents.length; i++) {
      if (this.documents[i].status === 'signed') signed++;
      if (this.documents[i].status === 'failed') failed++;
    }
    return {
      currentIndex: this.currentIndex,
      total: this.documents.length,
      signedCount: signed,
      failedCount: failed,
      restartCount: this.restartCount,
      isRunning: this.isRunning,
      isPaused: this.isPaused
    };
  };

  return ResilientBatchSigner;
});
