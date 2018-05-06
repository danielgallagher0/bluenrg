# BlueNRG

[![Build
Status](https://travis-ci.org/danielgallagher0/bluenrg.svg?branch=master)](https://travis-ci.org/danielgallagher0/bluenrg)

This crate is a provides the vendor-specific Bluetooth HCI for STMicro's BlueNRG
family of Bluetooth RF modules. It extends
[bluetooth-hci](https://github.com/danielgallagher0/bluetooth-hci) with
vendor-specific commands and events (and associated errors).

# BlueNRG and BlueNRG-MS

This crate supports both the older
[BlueNRG](http://www.st.com/resource/en/user_manual/dm00162667.pdf)
version of the HCI, and the newer
[BlueNRG-MS](http://www.st.com/en/wireless-connectivity/bluenrg-ms.html)
version. By default, the crate implements BlueNRG-MS.

# Work in Progress...

As you will notice, documentation is woefully lacking. This is still (as of
April 2018) actively developed, so more is on the way!
