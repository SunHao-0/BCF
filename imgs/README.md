## Disk Image

Please download the disk image from the following link which is permanently available:

```
TODO
```

The zip file `imgs.zip` contains the disk image (`bookworm.img`), the ssh key (`bookworm.id_rsa`), and the optional prebuilt kernel image (`bzImage`), which can be used to test if qemu boots the kernel correctly.

Inside the VM, we provided the prebuilt cvc5 (/usr/bin/cvc5) and bpftool (/usr/bin/bpftool) with BCF support.

#### How to use the disk image

Note: The provided ssh key is only for testing, please do not use it for any other purpose.

1. Download the disk image from the link above and unzip it
2. Change the file permission of the ssh key to 600
3. Boot the built kernel with the disk image using qemu
4. Login with `root` (no password) and the ssh key

```bash
> ./scripts/boot_vm.sh
> ssh -i imgs/bookworm.id_rsa -p 10023 root@localhost
```
