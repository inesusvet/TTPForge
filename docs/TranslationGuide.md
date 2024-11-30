# Atomic Red Team tests consumption by TTPForge

This doc provides step-by-step guide to migrate ART tests to TTPForge format and run them.


## Conventions of the source

Located in the [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) repo on github. The `atomics` directory contains a library of YAML files categorized by MITRE TTP ids as sub-directory names.
Each YAML file contains several _Atomic tests_ (or implementations) of the unique TTP.  Those tests differ by targeted platform, toolchain, and the actual way of acheiving the goal.
Each test might have unique parameters to be passed via command line, prerequisites and instructions to funlfill those prerequisites.
Executor is the program which is used to perform required actions to excersise the test.


## Steps required for translation

The TTPForge engine supports only one implementation of a TTP per file.  This is why you should expect several new files to appear in the target directory. By default the resulting YAML files have unique UUID as its name.  This UUID is taken from the corresponding  test.
Each resulting file has MITRE TTP id tags as well as platform requirements.
Resulting YAML file has all arguments defined in the corresponding Atomic test.

Please note that the Prerequisites concept is not supported by TTPForge engine.  This is why check for such prerequisites and their acquisition is kept as a separate step in the resulting YAML file.


## The guidance

0. Checkout the branch containing the translation script (see [the PR](https://github.com/inesusvet/TTPForge/pull/1) in my fork of TTPForge).
0. Install [the Mage](https://magefile.org/) build tool for Go in order to run the translation script.
0. Select a YAML file from the ART library to traslate to TTPForge format.
0. Run the translation script passing diretory containing the ART YAML file.
For example `mage convertYAMLSchema ~/atomic-red-team/atomics/T1003.002`
0. Test the translated YAML file with TTPForge.


## Testing

As the majority of Atomic tests are Windows specific, let's describe the testing approach using this platform.

0. Enable Windows Sandbox following [the official guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview) to evade EDR noise.
0. Download latest TTPForge binary [release](https://github.com/facebookincubator/TTPForge/releases) from github.
0. Run TTPForge on transalted YAML file using `--dry-run` mode
0. Run TTPForge for real life.


## Feedback
Please send your questions to the [original issue](https://github.com/facebookincubator/TTPForge/issues/83) on github.
