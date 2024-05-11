## Testing

```shell
py -m pip install pyyaml

# Note: the repos are quite large, so it is recommended to just download the latest version off github instead of cloning

# Tested on commit 5ec2cf7
git clone https://github.com/MicrosoftDocs/sdk-api
# Tested on commit 9a9fe38
git clone https://github.com/MicrosoftDocs/win32
cd auto-enum
python3 gen/windows/main.py
python3 gen/diff.py generated plugin/data/windows
```