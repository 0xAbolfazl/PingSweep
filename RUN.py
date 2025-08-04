from source.cli import ping_sweep_runner
from source.gui import main
from os import system

while True:
    user_choice = int(input('1. CLI Version\n2. GUI Version\n[?] Your choice : '))
    if user_choice == 1:
        system('cls')
        ping_sweep_runner()
        break
    elif user_choice == 2:
        system('cls')
        main()
        break
    else:
        print('Your choice must be between 1 and 2 !')