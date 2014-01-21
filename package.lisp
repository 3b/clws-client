(defpackage #:clws-client
  (:use #:cl)
  (:export
   #:on-connect
   #:on-close
   #:on-message
   #:send-message
   #:*web-socket*
   #:send-ping
   #:on-pong))