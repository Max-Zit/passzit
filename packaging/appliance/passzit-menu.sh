# PassZit appliance: the setup menu starts when pzadmin signs in on the
# server's own screen (not over SSH). Leave it for a command line; open it
# again with: sudo passzit-setup
case "$(tty 2>/dev/null)" in
/dev/tty[0-9]*)
    if [ "$(id -un)" = pzadmin ] && [ -z "${PZ_MENU_SHOWN:-}" ]; then
        export PZ_MENU_SHOWN=1
        sudo -n /usr/local/sbin/passzit-setup
    fi
    ;;
esac
