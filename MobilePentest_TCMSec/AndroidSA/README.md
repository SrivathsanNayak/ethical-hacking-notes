# Android Static Analysis

1. [Pulling an APK from the Play Store](#pulling-an-apk-from-the-play-store)
1. [Manual Static Analysis](#manual-static-analysis)
1. [Enumerating AWS Storage Buckets](#enumerating-aws-storage-buckets)
1. [Finding Hardcoded Strings](#finding-hardcoded-strings)
1. [Injured Android Static Analysis](#injured-android-static-analysis)
1. [Enumerating Firebase Databases](#enumerating-firebase-databases)
1. [Automated Analysis using MobSF](#automated-analysis-using-mobsf)

## Pulling an APK from the Play Store

* Under ```AVD Manager```, run the virtual device (configured with API level 29) - we need to navigate to the Google Play Store, sign into a Google account and download the ```Injured Android``` app (if you're unable to find the app on Play Store, download it from GitHub instead).

```shell
# after installing app on virtual device
# in Terminal in Android Studio

adb shell
# launches shell for virtual device

whoami
# shell

ls
# shows android files

pm list packages
# lists all installed apps

pm list packages | grep injured
# search for InjuredAndroid package
# shows package name 'b3nac.injuredandroid'

pm path b3nac.injuredandroid
# shows file path for app

exit
# exit shell
# we are on our system now

mkdir ApkFolder
# create directory for apk

cd ApkFolder

adb pull <file path for injuredandroid> injuredandroid-pulled.apk
# pulls the apk from device to system

# now we can open this apk
# and view source code in jadx-gui

# if the file cannot be opened in jadx-gui
# there is a Java version mismatch
```

## Manual Static Analysis

* [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) is the vulnerable app used in this course - it is made in the form of a CTF.

* The flags in the app can be tracked in the actual app as well.

* [```Android Manifest.xml``` file](https://developer.android.com/guide/topics/manifest/manifest-intro):

  * found in every Android app
  * where basics of app are defined
  * includes ```minSDKVersion```, [permissions](https://developer.android.com/reference/android/Manifest.permission), activities (UI elements in app) and content providers (to serve data from this app to other apps)

* In ```jadx-gui```, we can view the ```Android Manifest.xml``` file under ```Resources```, after opening the ```InjuredAndroid.apk``` pulled from the virtual device.

* This includes ```minSdkVersion``` - shows that it can run on Android API 21 and up.

* It also shows us the permissions used by the app under the ```<uses-permission>``` tag.

* We can look for activites and providers with the ```exported``` property set to ```True```.

* We can decompile the apk file for manual static analysis using ```apktool```.

```shell
apktool d injuredandroid-pulled.apk
# d for decompiling apk
# additionally, -r can be used
# for not decompiling resources in app, to save time

# this generates the files for apk
ls
# creates directory for the files

cd injuredandroid-pulled

ls
# contains files & folders for the app
```

* Upon decompiling, we get several files and folders - some of them were not visible in ```jadx-gui```.

* We can inspect these files further; for example, the ```smali``` folder contains the source code for the app, similar to how ```jadx-gui``` shows the code.

## Enumerating AWS Storage Buckets

* In ```InjuredAndroid```, Flag 8 is related to AWS CLI and AWS Storage.

* Searching for strings related to AWS leads us to ```strings.xml``` file, which can be an important resource in such cases.

* Decompiling using ```apktool``` gives us ```strings.xml``` at the path ```/res/values/```; in ```jadx-gui```, the file can be found at the path ```/Resources/resources.arsc/res/values/```.

* ```strings.xml``` includes the values for ```AWS_ID``` and ```AWS_SECRET``` - but the latest release of the apk has removed these values.

* With the ```AWS_ID``` and ```AWS_SECRET``` values, we can use tools such as [```cloud_enum```](https://github.com/initstring/cloud_enum) and ```awscli``` to get more information:

```shell
# setup cloud_enum tool from git

python3 cloud_enum.py -k injuredandroid
# fuzz for term 'injuredandroid'
# this can give us a s3 bucket for example

# setup awscli

aws configure --profile injuredandroid
# specify AWS_ID and AWS_SECRET in the prompt
# we can now try to get access to s3 bucket found earlier

aws s3 ls s3://injuredandroid --profile injuredandroid
# enum s3 bucket
```

## Finding Hardcoded Strings

* Often, hardcoded strings can be found in ```resources/strings.xml``` and activity source code.

* Threat vectors include login bypass (username/password, creds), URLs exposed (http/https), API keys exposed and Firebase URLS (firebase.io).

* In ```jadx-gui```, we can view the xml files in the path ```/Resources/resources.arsc/res/values/```.

* ```strings.xml``` contains interesting data such as ```default_web_client_id```, ```google_api_key```, ```google_app_id```, ```google_crash_reporting_api_key```, ```google_storage_bucket``` and ```firebase_database_url```; we can also use ```Ctrl+F``` to find certain keywords in the file.

* ```jadx-gui``` also allows searching all files for keywords, so we can search for keywords and terms like ```http://```, ```https://```, ```API```, ```password```, ```firebase``` and ```sql```.

## Injured Android Static Analysis

* Flag 1:

  * We can check source code for this in ```jadx-gui``` - it can be found in the path ```/Source code/b3nac.injuredandroid/FlagOneLoginActivity```.

  * The source code includes the flag ```F1ag_0n3```.

* Flag 2:

  * The clues given are ```activity``` and ```exported```.

  * In the ```AndroidManifest.xml``` file, we can search for the term ```exported=true```.

  * We can try the various results obtained by copying the activity name - for example, ```b3nac.injuredandroid.b25lActivity```.

  * These exported activities can be accessed from anywhere on our device.

  ```shell
  # invoke shell
  adb shell
  
  # to start activity from the app
  # add forward slash before activity name
  am start b3nac.injuredandroid/.b25lActivity

  # this starts the activity
  # and in the device, brings us to a new UI
  # here, we get our second flag
  ```

* Flag 3:

  * For this, the clue is related to 'Resources'.

  * We can check the source code for this flag as well - similar to flag 1, there is a string comparison done to check if the flag is correct.

  * But here, the comparison is done with ```R.string.cmVzb3VyY2VzX3lv```

  * The ```R.string``` part indicates that we could find this string in ```strings.xml``` file.

  * Searching for the ```cmVzb3VyY2VzX3lv``` part gives us flag 3.

* Flag 4:

  * The clue given is "classes and imports".

  * We can start by checking the source code for flag 4.

  * In the function where the flag comparison is done, we can see that a byte object is instantiated from a class ```C1489g```.

  * Double-clicking on the class name, or searching for it in all files leads us to the source code for this class.

  * This contains a base64-encoded string - decoding this gives us the flag.

## Enumerating Firebase Databases

* For flag 9, we have to enumerate Firebase databases.

* Earlier, from ```strings.xml```, we got a URL <https://injuredandroid.firebaseio.com>.

* For enumeration, we can use a tool like [firebaseEnum](https://github.com/Sambal0x/firebaseEnum).

* Here, we can go through the source code for flag 9 - the code gives us a 'decoded directory' string, which is a base64-encoded string - when decoded, it gives us the term 'flags/'.

* Now, when we try to interact with the URL in our browser, we are prompted to sign in - to avoid this, we can add ```.json``` at the end of our URL - like <https://injuredandroid.firebaseio.com/.json>

* If we check the 'flags/' directory in our URL - <https://injuredandroid.firebaseio.com/flags/.json> - this gives us the flag.

## Automated Analysis using MobSF

* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) can be used to automate the analysis of the apk.

```shell
# setup MobSF by cloning the repo
# and installing the dependencies using pip3

cd Mobile-Security-Framework-MobSF

./run.sh
# starts the tool
# we can now go to the given localhost link
```

* We can upload our apk into the static analysis section on MobSF - this generates a lot of information related to the app.
