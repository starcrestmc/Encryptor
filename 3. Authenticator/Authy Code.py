def authy():
    import random
    random = random.randint(100000,999999)

    f = open("code.txt", "w")
    f.write(str(random))
    f.close()

    import webbrowser
    webbrowser.open("code.txt")


    f = open("code.txt", "r")
    Password = f.readline()
    check = input("enter Authy code: \n")
    if check == Password:
        print("Password Correct")
        import os
        os.system("TASKKILL /F /IM notepad.exe")
        webbrowser.open("www.padlad256.wixsite.com/0101")
        f = open("code.txt", "w")
        f.write("######")
        f.close()
        exit()

    else:
        print("Incorrect Password")
        f = open("code.txt", "w")
        f.write(" ")
        f.close()
        exit()
authy()


