# A10ToAlteonConvertor

## Table Of Contents ###
- [Description](#description )
- [How To Use](#how-to-use )

## Description ##
The following script is used to convert AX (A10 Networks) configuration file to Alteon configuration.<br>
Supported Alteon versions are 32.0 and above (not tested on older versions).<br>
the script will create new files inside the working directory in the following manor:
* "Project name"\_cfg\_out.txt = Ready Alteon Config
* "Project name"\_logfile.txt = Commands not supported by the script
* "Project name"\_leftovers.txt = Configuration untouched by the script

## How To Use ##

In order to use the script make sure you have installed python3<br>
Download all git content and run the script while providing original file and project names as arguments<br>
For example : 
```
# git clone https://github.com/Radware/Linkproof-to-Alteon-Migration.git
# python convertor.py "a10_config.txt" "Project_Name"
```

