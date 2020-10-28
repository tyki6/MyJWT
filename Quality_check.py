import os
import sys


def quality_check():
    print("Checking Source code...", flush=True)
    print("----------------------------------------", flush=True)
    os.system("flake8 --max-line-length=150 --ignore=E401,W605 > dumpSyntax")
    errors = open("dumpSyntax", "r").read().splitlines()
    nbrErrors = len(errors)
    res = 0 if nbrErrors < 10 else 1
    for error in errors:
        print(f'{"(!)" if ": E" in error else "(-)"} {error}', flush=True)
    print("----------------------------------------", flush=True)
    print(f"Number of error: {nbrErrors}", flush=True)

    if res == 0:
        print("Passing Quality Check :D", flush=True)
    else:
        print("Need to improve the code :(", flush=True)
    sys.exit(res)


if __name__ == '__main__':
    quality_check()
