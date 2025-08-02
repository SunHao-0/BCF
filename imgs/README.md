## Disk Image

Please download the disk image from the following link which is permanently available (https://zenodo.org/records/16574189):

```
wget https://zenodo.org/records/16574189/files/imgs.zip?download=1 -O imgs.zip
```

The zip file `imgs.zip` contains the disk image (`bookworm.img`), the ssh key (`bookworm.id_rsa`), and the optional prebuilt kernel image (`bzImage`), which can be used to test if qemu boots the kernel correctly.

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

If you prefer, you can also use any existing disk image in your environment, just ensure: (1) it can be login via root without password; (2) the ssh key is in the `imgs` directory (change `vars.sh` if needed); and (3) there is a `bcf` directory in `/root` in the disk image, which is used for setting up the shared folder (see `scripts/boot_vm.sh`). No other changes are needed.

