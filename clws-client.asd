(defsystem :clws-client
  :depends-on (puri iolib babel cl-base64 clws conserv chunga)
  :serial t
  :components
  ((:file "package")
   (:file "client")
   (:file "client-protocol")))
