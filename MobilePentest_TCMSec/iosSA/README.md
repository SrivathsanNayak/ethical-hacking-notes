# iOS Static Analysis

1. [Intro](#intro)
2. [Manual Static Analysis](#manual-static-analysis)

## [Intro](https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06a-platform-overview)

* iOS devices are limited compared to Android; Apple utilizes a 'walled garden' of apps that can be installed - we can bypass this by Jailbreaking.

* ```xCode``` is the development environment for iOS.

* iOS devices have a hardware security component as well, which is not seen in Android commonly.

* Similar to Android, everything is based on Unix in iOS as well; and all apps are signed by Apple, and run in a sandbox environment.

* File system has 2 partitions - user partition (encrypted) and OS partition.

* Most iOS apps are based on ```Objective C``` - ```Swift``` is the latest code version though.

* Similar to ```.apk``` for Android, iOS uses ```.iPA``` format, which is a signed bundle of folders & assets.

* .ipa contains ```/Payload``` folder & some important files such as ```/Payload/Application.app/Info.plist``` (similar to ```AndroidManifest.xml```).

* To pull IPA from App Store, we can use tools like ```AnyTrans``` and ```IPATool```.

## Manual Static Analysis

* One approach is to rename the .ipa file to 'Payload.zip'; as the .ipa file is a bundled file, this works and we can extract the contents to a folder.

* Inside the folder, there will be a 'payload' folder, which includes an app - we can view its contents.

* Files of importance include ```info.plist```, and other .plist & .json files.

* For automated analysis, we can use ```MobSF``` tool.
