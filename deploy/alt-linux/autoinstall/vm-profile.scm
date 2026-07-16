((timeshiftstation
  (title . "Sosnadmin ALT workstation")
  (action . trivial)
  (actiondata
    ("swap"
      (size 8388608 . 8388608)
      (fsim . "SWAPFS")
      (methods plain))
    (""
      (size 83886080 . #t)
      (fsim . "BtrFS")
      (methods plain)
      (subvols ("@" . "/") ("@home" . "/home"))))))
