#!/bin/sh

# THIS SCRIPT RUNS INSIDE THE SO2 VM

ASSIGNMENT0_CHECKER=/home/root/skels/assignments/0-list-checker
ASSIGNMENT0_OUTPUT=/home/root/skels/0-list-output
ASSIGNMENT0_FINISHED=/home/root/skels/0-list-finished

ASSIGNMENT1_CHECKER=/home/root/skels/assignments/1-tracer-checker
ASSIGNMENT1_OUTPUT=/home/root/skels/1-tracer-output
ASSIGNMENT1_FINISHED=/home/root/skels/1-tracer-finished

ASSIGNMENT2_CHECKER=/home/root/skels/assignments/2-uart-checker
ASSIGNMENT2_OUTPUT=/home/root/skels/2-uart-output
ASSIGNMENT2_FINISHED=/home/root/skels/2-uart-finished


assign0_list()
{
        cd $ASSIGNMENT0_CHECKER
     	   sh _checker &> $ASSIGNMENT0_OUTPUT
       	   echo FINISHED &> $ASSIGNMENT0_FINISHED
        cd -
}

assign1_tracer()
{
        cd $ASSIGNMENT1_CHECKER
     	   sh _checker &> $ASSIGNMENT1_OUTPUT
       	   echo FINISHED &> $ASSIGNMENT1_FINISHED
        cd -
}

assign2_uart()
{
        cd $ASSIGNMENT2_CHECKER
     	   sh _checker &> $ASSIGNMENT2_OUTPUT
       	   echo FINISHED &> $ASSIGNMENT2_FINISHED
        cd -
}

start()
{
        local arg=$(cat /proc/cmdline | grep -o 'so2=[^ ]*' | cut -d= -f2)
        case "$arg" in
                0-list)
                        assign0_list
                        ;;
		1-tracer)
			assign1_tracer
			;;
		2-uart)
			assign2_uart
			;;
                *)
                        echo "Unknown option"
                        exit 0
                        ;;
        esac
}

# Carry out specific functions when asked to by the system
case "$1" in
        start)
                echo "Starting so2_vm_checker_daemon.sh..."
                start
                ;;
        stop)
                echo "Stopping so2_vm_checker_daemon.sh..."
                sleep 2
                ;;
        *)
                echo "Usage: /etc/init.d/foo {start|stop}"
                exit 1
                ;;
        esac

exit 0

