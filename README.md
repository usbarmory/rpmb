Replay Protected Memory Block (RPMB) driver
===========================================

This Go package implements Replay Protected Memory Block (RPMB) configuration
and control on eMMCs accessed through package
[usdhc](https://pkg.go.dev/github.com/usbarmory/tamago/soc/nxp/usdhc)
(TamaGo NXP uSDHC driver).

This package is meant to be to be used with `GOOS=tamago GOARCH=arm` as
supported by the [TamaGo](https://github.com/usbarmory/tamago) framework for
bare metal Go.

Authors
=======

Andrea Barisani  
andrea@inversepath.com  

Documentation
=============

[![Go Reference](https://pkg.go.dev/badge/github.com/usbarmory/rpmb/doc.svg)](https://pkg.go.dev/github.com/usbarmory/rpmb)

The package API documentation can be found on
[pkg.go.dev](https://pkg.go.dev/github.com/usbarmory/rpmb).

For more information about TamaGo see its
[repository](https://github.com/usbarmory/tamago) and
[project wiki](https://github.com/usbarmory/tamago/wiki).

License
=======

These source files are distributed under the Apache license found in the
[LICENSE](https://github.com/usbarmory/rpmb/blob/master/LICENSE) file.
