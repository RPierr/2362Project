import random
###############################################################
# Functions
def isInteger(user_input):
    try:
        int(user_input)
        return True
    except:
        return False

def compareNums(user_num, com_num):
    if user_num < com_num:
        print("Guess Higher!")
    elif user_num > com_num:
        print("Guess Lower!")
    else:
        print("Well Done! The number was", com_num)
        return True

def range():

    lower = 0
    upper = 0
    done = False

    while not done:
        lower = input("Enter the number for the lower bound: ")
        if isInteger(lower) == True:
            lower = int(lower)
        else:
            print("Wanna try again?")
            continue

        upper = input("Enter the number for the upper bound: ")
        if isInteger(upper) == True:
            upper = int(upper)
        else:
            print("Do you know what a number is? Start over.")
            continue

        if lower > 0 and upper > 0:
            done = True


    return lower, upper

def guessNumber():
    lower, upper = range()
    com_num = random.randint(lower, upper)
    wrong_guesses = 0
    threshold = (upper - lower + 1) // 2
    threshMet = False

    while True:
        user_input = input(f"Guess a number between {lower} and {upper}: ")
        if isInteger(user_input):
            user_num = int(user_input)
            if compareNums(user_num, com_num):
                break
            else:
                wrong_guesses += 1
                if wrong_guesses >= threshold and not threshMet:
                    print(f"You have guessed wrong {wrong_guesses} times, which is 50% or more of the available numbers. Impressive")
                    threshMet = True
        else:
            print("That's not a number >:[")
    askForTip()

def askForTip():
    tip = input("Would you like to leave a tip for the game? (yes/no): ")
    if tip.lower() == 'yes':
        amount = input("Enter the tip amount: ")
        if isInteger(amount):
            print(f"Thank you for your generous tip of {amount}!")
        else:
            print("That's not a tip! You trying to cheat me?!")
    else:
        print("No tip? Didn't you like the game? :(")

###############################################################

# Main
guessNumber()