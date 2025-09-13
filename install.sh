#!/bin/sh

RESOURCES="structutils_resources"
SCRIPT="structutils.py"

PLUGIN_DIR="$HOME/.idapro/plugins"
RESOURCES_DIR="$PLUGIN_DIR/$RESOURCES"
SCRIPT_DIR="$PLUGIN_DIR/$SCRIPT"

# Uninstall function
uninstall() {
    if [ ! -d "$RESOURCES_DIR" ] && [ ! -f "SCRIPT_DIR" ]; then
        echo "ℹ️  Nothing to uninstall. Directory '$RESOURCES_DIR' and file '$SCRIPT_DIR' do not exist."
        exit 0
    fi

    echo "⚠️  This will delete the installed directory at '$RESOURCES_DIR' and the file $'$SCRIPT_DIR'"
    echo -n "Are you sure you want to uninstall? [y/N]: "
    read confirm

    case "$confirm" in
        [yY]|[yY][eE][sS])
            echo "Uninstalling..."
            rm -rf $RESOURCES_DIR $SCRIPT_DIR
            if [ $? -eq 0 ]; then
                echo "✅ Uninstallation complete."
            else
                echo "❌ Failed to delete all files"
                exit 1
            fi
            ;;
        *)
            echo "Uninstallation cancelled."
            exit 0
            ;;
    esac
}

if [ "$1" = "--uninstall" ]; then
    uninstall
    exit 0
fi


# Create plugins directory if it doesn't exist
if [ ! -d "$PLUGIN_DIR" ]; then
    echo "IDA plugin directory'$PLUGIN_DIR' does not exist. Creating it..."
    mkdir -p "$PLUGIN_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create plugin directory. Aborting."
        exit 1
    fi
fi

# Check if destination directory exists
if [ -d "$RESOURCES_DIR" ] || [ -f "$SCRIPT_DIR" ]; then
    echo "⚠️  A previous installation of structutils exists"
    echo "Installing will overwrite the previous version"
    echo -n "Do you want to continue? [y/N]: "
    read answer

    case "$answer" in
        [yY]|[yY][eE][sS])
            echo "Proceeding with installation..."
            rm -rf $RESOURCES_DIR SCRIPT_DIR
            ;;
        *)
            echo "Installation cancelled."
            exit 0
            ;;
    esac
fi


# Copy the contents of the folder
echo "Copying files..."
cp -r "$RESOURCES" "$PLUGIN_DIR/"
if [ $? -ne 0 ]; then
    echo "An error occurred during copy. Installation failed."
    exit 1
fi
cp "$SCRIPT" "$PLUGIN_DIR/"
if [ $? -eq 0 ]; then
    echo "✅ Installation complete."
else
    echo "❌ An error occurred during the copy. Installation failed."
    exit 1
fi