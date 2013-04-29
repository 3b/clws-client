(in-package #:clws-client)

#++
(asdf:load-systems 'puri 'iolib 'babel 'cl-base64 'clws 'conserv 'chunga)

;; possible api:
;; CALLBACK is called for every chunk of data

;;; simple single-thread API
;;;
;;  (CONNECT "uri" protocol(s) &key callback streaming origin (block t)) -> connection
;;    if STREAMING, doesn't combine fragments into frames
;;  (SEND connection string) ;; utf-8 encode string and send
;;  (SEND connection octet-vector) ;; send octet vector as-is
;;  (READ-FRAGMENT connection &key block)
;;  (WITH-WS-CONNECTION (v "uri" protocol(s) &key <same as connect> ) &body)
;;  (DO-FRAGMENTS ((fragvar &optional con-var) &rest connections) &body)
;;  (DO-FRAMES ((frame-var &optional con-var) &rest connections) &body)

(defclass frame ()
  ((opcode :accessor opcode :initform nil :initarg :opcode)
   (fin :accessor fin :initform nil :initarg :fin)
   (res1 :initarg :rsv1)
   (res2 :initarg :rsv2)
   (res3 :initarg :rsv3)
   (mask :accessor mask :initarg :mask)
   (data :accessor data :initarg :data)
   (size :accessor size :initform 0)))

(defclass web-socket ()
  ((url :reader url :initarg :url)
   (driver :reader driver :initarg :driver)
   (protocols :reader protocols :initarg :protocols :initform nil)
   (extensions :reader extensions :initarg :extensions :initform nil)
   (origin :reader origin :initarg :origin :initform nil)
   ;; status = :created :connecting :open :closing :closed
   (connect-status :reader connect-status :initform :created)
   ;; will error before trying to read frames larger than MAX-FRAME-SIZE
   (max-frame-size :accessor max-frame-size :initarg :max-frame-size
                   :initform (expt 2 20))
   ;; will error after reading more than MAX-MESSAGE-SIZE octets if
   ;; message isn't complete
   ;; (so might go over by up to MAX-FRAME-SIZE octets)
   (max-message-size :accessor max-message-size :initarg :max-message-size
                     :initform (expt 2 20))

   ;;
   (%socket :accessor %socket :initform nil)
   (%handshake-nonce)
   (%headers :accessor %headers :initform nil)
   (%partial-message :accessor %partial-message :initform nil)
   (%read-buffer :reader %read-buffer
                 :initform (make-instance 'clws::chunk-buffer))
   (%read-offset :accessor %read-offset :initform nil)
   (%frame :accessor %frame :initform nil)
   (%state :accessor %state :initform nil)
   (%match :accessor %match :initform nil)))

#++
(defmethod ws-open ((ws web-socket) &key)
  ;; todo: non-blocking connect?
  ;; (probably needs separate threads/callbacks etc to finish handshake
  ;;  after returning to caller though, so just blockingf or now)
  ;; fixme: decide if this should support reopening closed connections, etc
  (assert (not (%socket ws)))
  (setf (%socket ws) (iolib:make-socket
                      :external-format '(unsigned-byte 8)))
  (iolib:connect (%socket ws) (iolib:lookup-hostname (puri:uri-host (url ws)))
                 :port (puri:uri-port (url ws)) :wait t)
  (setf (slot-value ws 'connect-status) :connecting)
  ;; send handshake
  (send ws (opening-handshake (url ws) (origin ws) (protocols ws) (extensions ws)))
  ;; read octets until we get end of headers
  )

(defmethod ws-close ((ws web-socket) reason &key (block t))
  (%send-close ws 1000 reason))

(defmethod initialize-instance :after ((ws web-socket) &key)
  (when (stringp (url ws))
    (setf (slot-value ws 'url) (puri:parse-uri (url ws))))
  (setf (slot-value ws 'protocols) (alexandria:ensure-list (protocols ws)))
  (setf (slot-value ws 'extensions) (alexandria:ensure-list (extensions ws))))

(defparameter *web-socket* nil)

(defmethod conserv.tcp:on-tcp-client-close ((driver web-socket))
  (format t "client closed~%")
  (on-close (driver driver) 1006 ""))

(defmethod conserv.tcp:on-tcp-client-connect ((driver web-socket))
  (format t "client connected~%")
  (write-sequence (opening-handshake driver)
                  conserv.tcp:*tcp-client*)
  (enter-state driver :read-status-line))

;; conserv.tcp:on-tcp-client-data method defined in client-protocol.lisp

(defmethod conserv.tcp:on-tcp-client-end-of-file ((driver web-socket))
  (format t "client got eof~%"))

(defmethod conserv.tcp:on-tcp-client-error ((driver web-socket) error)
  (format t "client got error ~s~%" error))

(defmethod conserv.tcp:on-tcp-client-output-empty ((driver web-socket))
  (format t "client got output empty~%"))


(defmethod ws-connect (driver url &key protocols (origin nil)
                                    extensions)
  (let ((ws (make-instance 'web-socket
                           :driver driver
                           :url url
                           :protocols protocols
                           :extensions extensions
                           :origin origin)))
    (setf (%socket ws)
          (conserv.tcp::tcp-connect ws
                                    (puri:uri-host (url ws))
                                    :port (or (puri:uri-port (url ws)) 80)
                                    :wait t
                                    :external-format-in nil
                                    ;; only ever send text for HTTP headers,
                                    ;; since everything else gets masked
                                    :external-format-out :ascii))
    ))



;; sample use

(defclass wsc-sample ()
  ())

(defmethod on-message ((driver wsc-sample) message type)
  (format t "got message ~s~%" message)
  (if (and (< (length message) 128) (string/= message "done"))
    (send-message *web-socket* (format nil "got ~s!" message))
    (send-message *web-socket* "done"))
  (sleep 0.2)
  (when (equal message "done")
    (ws-close *web-socket* "got done")))

(defmethod on-close ((driver wsc-sample) code reason)
  (format t "closed, ~s ~s~%" code reason)
  (conserv:exit-event-loop :delay 0.1))

(conserv:with-event-loop ()
  (ws-connect (make-instance 'wsc-sample)
              "ws://localhost:12345/wsc-test"
              :origin "http://localhost"))

(setf clws::*log-level* t)
