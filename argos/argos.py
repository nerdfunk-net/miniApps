#!/usr/bin/env python

from prompt_toolkit import PromptSession
from argos.argos import Argos
import re
import sys


def parse_input(argos, input):

    m = re.match("^username (\S+)", input)
    if m:
        argos.set_username(m.group(1))

    m = re.match("^password (\S+)", input)
    if m:
        argos.set_password(m.group(1))

    m = re.match("^platform (\S+)", input)
    if m:
        argos.set_platform(m.group(1))

    m = re.match("^open (\S+)", input)
    if m:
        argos.open(m.group(1))

    m = re.match("^close", input)
    if m:
        argos.close()

    m = re.match("^(quit|exit|q)", input)
    if m:
        argos.close()
        sys.exit()

    m = re.match("^(sh|sho|show) .*", input)
    if m:
        argos.show(m.group(0))


if __name__ == "__main__":

    # Create prompt object.
    session = PromptSession('> ')
    argos = Argos("lab", "lab")

    while True:
        input = session.prompt()
        parse_input(argos, input)