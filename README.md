# CoKey Token USB Armory Linux Tree

This repository contains the Linux tree for using the USB Armory as a CoKey
token. For further details regarding CoKey see the corresponding paper
publication on ACSAC 2016:

    J. Horsch, S. Wessel and C. Eckert. CoKey: Fast Token-Based Cooperative
    Cryptography. In Proceedings of the 32th Annual Computer Security
    Applications Conference, ACSAC ’16. ACM, 2016.

Note that this is a **Proof of Concept (PoC)** implementation and should **not**
be used in a productive environment.

The Linux tree is basically a mainline kernel including two non-mainline
components which are the driver for the i.MX Security Controller (SCC) and the
CoKey USB gadget function driver.

## TODOs

See `drivers/usb/gadget/function/f_cokey.c` for a list of TODOs for the CoKey
gadget driver.

## Installation

Build the Linux kernel (see other guides for that) using the provided
configuration file for kernel version 3.19 or make sure that your
configuration file enables relevant USB Gadget functions and the CoKey
specific configuration options (`CONFIG_USB_F_COKEY` and `CONFIG_USB_CONFIGFS_F_COKEY`).

## Usage

After building and deploying the Linux kernel to the USB armory, you can use
the USB Linux gadget configfs to configure the USB armory at runtime to expose
a CoKey USB interface to the connected host.  The CoKey USB interface can also
be combined with other USB interfaces, for example, a network and a serial
interface.

Note that on the host you need the CoKey host driver loaded to be able to use
CoKey driven crypto algorithms.

The following **example** commands assume that configfs is mounted to
`/sys/kernel/config` and configure a USB gadget that exposes two serial, one
network and a CoKey interface to the connecting host:

        cd /sys/kernel/config/usb_gadget/

        # Create a new gadget
        mkdir g1 && cd g1
        
        # This seems to be mandatory for Mac Hosts
        echo 0x0200 > bcdUSB
        
        # Configure Vendor and Product IDs
        echo "0x1d6b" > idVendor
        echo "0x0104" > idProduct
        #echo 0x02 > bDeviceClass
        
        # Configure strings to describe the device to the host
        mkdir strings/0x409
        echo "0123456789" > strings/0x409/serialnumber
        echo "Foo Inc." > strings/0x409/manufacturer
        echo "Bar Gadget" > strings/0x409/product
        
        # Create function instances
        mkdir functions/acm.GS0
        mkdir functions/acm.GS1
        mkdir functions/ecm.usb0
        mkdir functions/cokey.cu0
        
        # Create a USB configuration for the device
        mkdir configs/c.1
        # Describe configuration
        mkdir configs/c.1/strings/0x409
        echo "CDC 2xACM+ECM+CoKey" > configs/c.1/strings/0x409/configuration
        
        # Include functions into configuration
        ln -s functions/acm.GS0 configs/c.1
        ln -s functions/acm.GS1 configs/c.1
        ln -s functions/ecm.usb0 configs/c.1
        ln -s functions/cokey.cu0 configs/c.1
        
        # Enable device mode in controller
        echo "ci_hdrc.0" > UDC

## License

The CoKey USB gadget driver is licensed under GPLv2.
