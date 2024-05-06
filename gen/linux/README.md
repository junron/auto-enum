## Testing

Linux system with gcc installed required.

```shell
# Tested on commit ae6b221
git clone https://github.com/mkerrisk/man-pages
cd auto-enum
python3 gen/linux/main.py
python3 gen/diff.py generated plugin/data/linux
```