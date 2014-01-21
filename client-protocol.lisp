(in-package #:clws-client)


(defparameter *ascii-crlf* (babel:make-external-format :ascii
                                                       :eol-style :crlf))

(defun opening-handshake (ws)
  (babel:string-to-octets
   ;; todo: optional proxy password header?
   (format nil "GET ~a HTTP/1.1
Host: ~a
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ~a
~@[Origin: ~a~%~]~
Sec-WebSocket-Version: 13
~@[Sec-WebSocket-Protocol: ~{~a~^, ~}~%~]~
~@[Sec-WebSocket-Extensions: ~{~a~^, ~}~%~]~

"
           (puri:uri-path (url ws))
           (puri:uri-host (url ws))
           (setf (slot-value ws '%handshake-nonce)
                 (base64:usb8-array-to-base64-string
                  (coerce (loop repeat 16 collect (random 256))
                          '(vector (unsigned-byte 8)))))
           ;; todo: add option to use scheme/host/port from url for origin
           ;; instead of explicit origin?
           (origin ws)
           (protocols ws)
           (extensions ws))
   :encoding :ascii))

(defmethod next-state (state &rest args)
  (throw 'next-state (list state args)))


;; matchers take a ub8 buffer and start/end indices, and return either
;; offset of end of match in buffer
;; or nil for no match (yet)

(defun octet-count-matcher (n)
  (let ((read 0))
    (lambda (buffer start end)
      (declare (ignore buffer))
      (let ((c (- end start)))
        (if (>= (+ read c) n)
            (+ start (- n read))
            (progn
              (incf read c)
              nil))))))

(defun octet-pattern-matcher (octets)
  (let ((matched 0)
        (read 0)
        (next (make-array (length octets) :initial-element 0
                                          :element-type 'fixnum)))
    ;; find next shortest sub-string that could be a match for current
    ;; position in octets. for example if we have matched "aaa" from "aaab"
    ;; and get another "a", we should reset match to "aa" rather than
    ;; starting over completely (and then add the new "a" to end up back at
    ;; "aaa" again)
    ;; -- probably should add a compiler macro to do this in advance for
    ;;    the usual case of constant pattern?
    (loop
      with matches = 0
      for i from 1 below (length octets)
      when (= (aref octets matches) (aref octets i))
        do (incf matches)
      else do (setf matches 0)
      do (setf (aref next i) matches))
    (lambda (buffer start end)
      (flet ((match-octet (x)
               (loop
                 do (if (= x (aref octets matched))
                        (return (incf matched))
                        (setf matched (aref next matched)))
                 while (plusp matched))))
        (loop
          for i from 0
          for bi from start below end
          do
             (incf read)
             (match-octet (aref buffer bi))
          when (= matched (length octets))
            return (1+ bi))))))

(defmethod get-match-octet ((ws web-socket))
  (clws::read-octet (%read-buffer ws)))

(defmethod get-match-as-vector ((ws web-socket))
  (clws::get-octet-vector (%read-buffer ws)))

(defun dispatch-message (ws octet-count frames)
  (flet ((get-octets ()
           (let ((b (make-array octet-count :element-type '(unsigned-byte 8))))
             (loop for frame in frames
                   for start = 0 then end
                   for end = (+ start (length (data frame)))
                   do (replace b (data frame) :start1 start :end1 end))
             b)))
    (ecase (opcode (car frames))
      (1
       ;; not sure if we should have separate binary and text message
       ;; methods, or just let drivers specialize the type of the message?
       ;; no way to get just binary messages though, since strings are vectors
       (let ((s (babel:octets-to-string (get-octets) :errorp nil)))
         (unless s
           (next-state :fail 1007 "failed to decode text message"))
         (on-message (driver ws) s :string)))
      (2
       (on-message (driver ws) (get-octets) :binary)))))

(defmethod on-frame-data (driver frame)
  ;; by default, just accumulate into a whole message before passing to client
  (let ((ws *web-socket*))
    (if (zerop (opcode frame))
        (assert (%partial-message ws))
        (assert (not (%partial-message ws))))
    (push frame (%partial-message ws))
    (let ((l (reduce '+ (%partial-message ws)
                     :key (lambda (a) (length (data a))))))
      (when (and (not (fin frame))
                 (> l (max-message-size ws)))
        (next-state :fail 1009 "message too large"))
      (when (fin frame)
        (dispatch-message ws l (reverse (shiftf (%partial-message ws) nil)))))
)
)

(defmethod %send-close ((ws web-socket) &optional code reason)
  (let ((reason (if (stringp reason)
                    (babel:string-to-octets reason
                                            :encoding :utf-8)
                    reason))
        (code (when code
                (vector (ldb (byte 8 8) code)
                        (ldb (byte 8 0) code)))))
    (send-frame ws #x8 t (concatenate '(vector (unsigned-byte 8))
                                      code reason))))
;;; state machine states:
;; opening - send handshake -> read headers
;; read headers - wait for crlf, split on =, etc until crlfcrlf -> check headers
;; check headers - check server response -> read frame
;; read masking value (16 octets)
;; read frame - read a frame -> finish frame
;; finish frame - send frame to client (or handle control frames) -> read frame
;;   (default frame handler for clients buffers fragmented messages,
;;    and sends whole messages to client)


(defmacro defstate (name (var &rest args) &body body &key entry exits)
  (declare (ignore body))
  (alexandria:with-gensyms (rest thunk state)
    `(defmethod enter-state ((,var web-socket) (state (eql ,name)) &rest ,rest)
       (destructuring-bind ,args ,rest
         ,entry
         (let ((,state nil))
           ,@(loop for (test . body) in exits
                   collect `(let ((,thunk ,test))
                              (push (list ,thunk (lambda () ,@body))
                                    ,state)))
           (setf (%state ,var) (reverse ,state)))))))

(defun validate-headers (ws)
  (format t "todo: validate headers ~s~%" (alexandria:hash-table-alist
                                           (%headers ws)))
  t)

(defstate :read-status-line (ws)
  :exits (((octet-pattern-matcher #(13 10))
           (let* ((b (get-match-as-vector ws))
                  (s (babel:octets-to-string b
                                             :encoding :iso-8859-1
                                             :end (- (length b) 2))))
             (unless (string= s "HTTP/1.1 101 Switching Protocols")
               (next-state :fail 1002 ""))
             (next-state :read-headers)))))

(defstate :read-headers (ws)
  :exits (((octet-pattern-matcher #(13 10 13 10))
           (let ((headers (clws::with-buffer-as-stream ((%read-buffer ws) s)
                            (chunga:read-http-headers s))))
             (setf (%headers ws)
                   (alexandria:alist-hash-table headers))
             (if (validate-headers ws)
                 (let ((*web-socket* ws))
                   (on-connect (driver ws))
                   (next-state :read-frame-start))
                 (next-state :fail 1002 "invalid headers"))))
          ((octet-count-matcher 65536)
           ;; possibly should limit per header line instead of all headers?
           ;; not sure if this should be 1008 or 1009? (or 1002 if http
           ;; spec specifies a limit on header size?)
           (next-state :fail 1008 "headers too long"))))

(defstate :read-frame-start (ws)
  :exits (((octet-count-matcher 2)
           (let* ((opcode (get-match-octet ws))
                  (len1 (get-match-octet ws))
                  (len (ldb (byte 7 0) len1)))
             (setf (%frame ws)
                   (make-instance 'frame
                                  :opcode (ldb (byte 4 0) opcode)
                                  :fin (logbitp 7 opcode)
                                  :rsv1 (logbitp 6 opcode)
                                  :rsv2 (logbitp 5 opcode)
                                  :rsv3 (logbitp 4 opcode)
                                  :mask (logbitp 7 len1)))
             (case len
               (127
                (next-state :read-length-64))
               (126
                (next-state :read-length-16))
               (t
                (setf (size (%frame ws)) len)
                (if (mask (%frame ws))
                    (next-state :mask-key)
                    (next-state :frame-payload))))))))

(defstate :read-length-16 (ws)
  :exits (((octet-count-matcher 2)
           (let ((len (logior (ash (get-match-octet ws) 8)
                              (get-match-octet ws))))
             (when (> len (max-frame-size ws))
               (next-state :fail 1009 "frame too large"))
             (setf (size (%frame ws)) len)
             (if (mask (%frame ws))
                 (next-state :mask-key)
                 (next-state :frame-payload))))))

(defstate :read-length-64 (ws)
  :exits (((octet-count-matcher 8)
           (let ((len (loop for i from 7 downto 0
                            sum (ash (get-match-octet ws) (* i 8)))))
             (when (> len (max-frame-size ws))
               (next-state :fail 1009 "frame too large"))
             (setf (size (%frame ws)) len)
             (if (mask (%frame ws))
                 (next-state :mask-key)
                 (next-state :frame-payload))))))


(defstate :mask-key (ws)
  :exits (((octet-count-matcher 4)
           (setf (mask (%frame ws)) (get-match-as-vector ws))
           (next-state :frame-payload))))


(defun dispatch-frame (ws)
  (let ((frame (%frame ws))
        (*web-socket* ws))
    (when (mask frame)
      (error "fixme: masked frame from server?"))
    (case (opcode frame)
      ((#x0 #x1 #x2) ;; cont /  text / binary
       (on-frame-data (driver ws) frame)
       (values :read-frame-start))
      (#x8 ;; close
       (let ((code (logand (ash (aref (data frame) 0) 8)
                           (aref (data frame) 1)))
             (reason (ignore-errors (babel:octets-to-string (data frame)
                                                            2))))
         (values :close code reason t)))
      (#x9 ;; ping
       (when (eq (connect-status ws) :open)
         (send-frame ws #xa t (data frame)))
       (values :read-frame-start))
      (#xa ;; pong
       ;; might as well send it to client, in case it wants to use it
       ;; to measure latency or something...
       (on-pong (driver ws) (data frame))
       (values :read-frame-start))
      (t
       (values :fail 1002 "unknown opcode")))))

(defstate :frame-payload (ws)
  :exits (((octet-count-matcher (size (%frame ws)))
           (setf (data (%frame ws))
                 (get-match-as-vector ws))
           (multiple-value-call #'next-state (dispatch-frame ws)))))


(defstate :close (ws code reason from-server)
  :entry (cond
           (from-server
            ;; if we get a close from server and are in closing,
            ;; it is a reply to our close (or both sent at same time)
            ;; so close the socket
            (when (eq (connect-status ws) :closing)
              (close (%socket ws)))
            (on-close (driver ws) (or code 1005) reason))
           (t
            (%send-close ws (or code 1000)
                         (or reason ""))
            (setf (slot-value ws 'connect-status) :closing))))


(defstate :fail (ws code reason)
  :entry (progn
           (%send-close ws code
                       (babel:string-to-octets (or reason "")))
           (close (%socket ws) :abort t)
           (on-error (driver ws) code reason)
           (setf (slot-value ws 'connect-status) :closed)))

(defmethod conserv.tcp:on-tcp-client-data ((ws web-socket) data)
  (loop with start = 0
        with end = (length data)
        for (next args) = (catch 'next-state
                            (loop for (test exit) in (%state ws)
                                  for match = (or (eq test t)
                                                  (funcall test data start end))
                                  ;; if we got a match, add a chunk for the
                                  ;; matching part, then call the
                                  ;; exit edge (which should call next-state)
                                  when match
                                    do (clws::add-chunk (%read-buffer ws)
                                                        data start match)
                                       (setf start match)
                                       (funcall exit)
                                       (error "broken state machine?"))
                            ;; if we got here, none of the tests matched, so
                            ;; just store whatever is left of the buffer
                            (unless (= start end)
                              (clws::add-chunk (%read-buffer ws)
                                                        data start end))
                            ;; and return nil to exit outer loop
                            nil)
        while next
        do (apply #'enter-state ws next args)))

(defmethod send-frame ((ws web-socket) opcode fin payload)
  (flet ((size-octets (x)
           (cond ((< x 126) (values 0 x))
                 ((< x 65536) (values 2 126))
                 (t (values 8 127)))))
    (let* ((l (length payload))
           (buf (make-array (+ 2 (size-octets l) 4 l)
                            :element-type '(unsigned-byte 8)))
           (i -1)
           (mask (make-array 4 :element-type '(unsigned-byte 8)
                             :initial-contents (loop repeat 4
                                                     collect (random 256)))))
      (check-type opcode (unsigned-byte 4))
      (setf (aref buf (incf i)) (logior (if fin #x80 0) opcode))
      (setf (aref buf (incf i)) (logior #x80 (nth-value 1 (size-octets l))))
      (when (< 125 l 65536)
        (setf (aref buf (incf i)) (ldb (byte 8 8) l)
              (aref buf (incf i)) (ldb (byte 8 0) l)))
      (when (<= 65536 l)
        (loop for i from 7 downto 0
              do (setf (aref buf (incf i)) (ldb (byte 8 (* i 8)) l))))
      (loop for m across mask
            do (setf (aref buf (incf i)) m))
      (loop for j from 0
            for maskj = (aref mask (mod j 4))
            for b across payload
            do (setf (aref buf (incf i)) (logxor maskj b)))
      #++(format t "~&send frame ~s~% = ~s~%"
              buf (babel:octets-to-string buf :encoding :iso-8859-1))
      (write-sequence buf (%socket ws))
)

)
  )
;; do we want to support any other message types besides string and binary?
;; some sort of json maybe?
(defmethod send-message ((ws web-socket) (message string))
  (send-frame ws #x1 t (babel:string-to-octets message :encoding :utf-8)))

(defmethod send-message ((ws web-socket) (message vector))
  ;; message should only contain (unsigned-byte 8), not sure if there is
  ;; any point in requiring types arrays though?
  (send-frame ws #x2 t message))

(defmethod send-ping ((ws web-socket) payload)
  (when (stringp payload)
    (setf payload (babel:string-to-octets payload :encoding :utf-8)))
  (send-frame ws #x9 t (or payload (make-array 0 :element-type '(unsigned-byte 8)))))