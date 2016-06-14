#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"
PS1=$; unset PROMPT_COMMAND
echo -en "\033]0;Spider Whisperer\a"
sudo DEBUG=* npm start
