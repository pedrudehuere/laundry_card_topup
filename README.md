Laundry card top up
===================

Top up the credit on a very specific type of NFC laundry card

The B key for sectors 1 and 2 must be provided
(see [here](https://github.com/nfc-tools/miLazyCracker) how to get it)

# Dependencies

```shell
$ sudo apt install libnfc-bin libfreefare-bin
```

Tested on Ubuntu 22.04 with `libnfc-bin 1.8.0-2` and `libfreefare-bin 0.4.0-2.1build1`


# Example usages

## Show current credit

```shell
$ ./topup 97a4e7fe952c
The current credit value is 1.50
```

## Set credit

```shell
$ ./topup -s 50 97a4e7fe952c
The current credit value is 1.50
Credit set to 50.00

$ ./topup 97a4e7fe952c
The current credit value is 50.00
```

## Verbose output

```shell
$ ./topup -v 97a4e7fe952c
Using B key 97a4e7fe952c to authenticate to sectors 0x01 and 0x02
Using libnfc 1.8.0
Using libfreefare <unknown version>
Listing devices...
Found 1 device(s):
 - pn532_uart:/dev/ttyUSB0
Using pn532_uart:/dev/ttyUSB0
Open pn532_uart:/dev/ttyUSB0
Adafruit PN532 board via UART ready
Using tag Mifare Classic 1k with ID c45ceced
The current credit value is 50.00
``` 

# Links

 - [libnfc](https://github.com/nfc-tools/libnfc)
 - [libfreefare](https://github.com/nfc-tools/libfreefare)
