-- PacketPoet Wireshark Plugin
-- Adds "Tools → Send to PacketPoet" menu to export captures to narrative

-- Configuration
local PACKETPOET_PATH = os.getenv("HOME") .. "/packetpoet/main.py"

-- Check if PacketPoet is installed
local function check_packetpoet()
    local test_path = os.getenv("PACKETPOET_PATH") or PACKETPOET_PATH
    local file = io.open(test_path, "r")
    if file then
        file:close()
        return test_path
    end
    return nil
end

-- Export current capture file to PacketPoet
local function export_to_packetpoet(style)
    local poet_path = check_packetpoet()
    if not poet_path then
        os.execute("zenity --error --text='PacketPoet not found. Check PACKETPOET_PATH' 2>/dev/null")
        return
    end
    
    -- Get current capture file path
    local capture_file = get_current_file()
    
    if not capture_file or capture_file == "" then
        -- No file open - need to save current capture first
        local tmpfile = os.tmpname() .. ".pcap"
        
        -- Save current capture using dumpcap
        local save_cmd = string.format("dumpcap -i any -a duration:2 -w '%s' 2>/dev/null", tmpfile)
        os.execute(save_cmd)
        
        capture_file = tmpfile
    end
    
    -- Create temp file for processed output
    local tmpfile = os.tmpname() .. ".pcap"
    
    -- Copy to temp location (so we don't modify original)
    local cp_cmd = string.format("cp '%s' '%s' 2>/dev/null", capture_file, tmpfile)
    os.execute(cp_cmd)
    
    -- Launch PacketPoet in terminal
    local term_cmd = string.format(
        "x-terminal-emulator -e 'cd %s && source venv/bin/activate && python3 %s read %s --style %s; echo \"Press Enter to close...\"; read' &",
        os.getenv("HOME") .. "/packetpoet",
        poet_path,
        tmpfile,
        style or "interactive"
    )
    
    -- Try different terminal emulators
    local result = os.execute(term_cmd)
    
    if not result then
        -- Try gnome-terminal
        local gnome_cmd = string.format(
            "gnome-terminal -- bash -c 'cd %s && source venv/bin/activate && python3 %s read %s --style %s; echo \"Press Enter to close...\"; read' &",
            os.getenv("HOME") .. "/packetpoet",
            poet_path,
            tmpfile,
            style or "interactive"
        )
        result = os.execute(gnome_cmd)
    end
    
    if not result then
        -- Try xterm
        local xterm_cmd = string.format(
            "xterm -e 'cd %s && source venv/bin/activate && python3 %s read %s --style %s; read' &",
            os.getenv("HOME") .. "/packetpoet",
            poet_path,
            tmpfile,
            style or "interactive"
        )
        result = os.execute(xterm_cmd)
    end
    
    if not result then
        print("PacketPoet command:")
        print(string.format("python3 %s read %s --style %s", poet_path, tmpfile, style or "interactive"))
    end
end

-- Create menu items
local function create_menu()
    -- Register menu items in Tools menu
    register_menu("Tools/PacketPoet/Interactive Style", function() 
        export_to_packetpoet("interactive") 
    end, MENU_TOOLS_UNSORTED)
    
    register_menu("Tools/PacketPoet/Spy Thriller", function() 
        export_to_packetpoet("spy") 
    end, MENU_TOOLS_UNSORTED)
    
    register_menu("Tools/PacketPoet/Cyberpunk", function() 
        export_to_packetpoet("cyberpunk") 
    end, MENU_TOOLS_UNSORTED)
    
    register_menu("Tools/PacketPoet/Technical Report", function() 
        export_to_packetpoet("technical") 
    end, MENU_TOOLS_UNSORTED)
    
    register_menu("Tools/PacketPoet/About", function() 
        os.execute("zenity --info --text='PacketPoet v0.1.0\\nNetwork traffic as literature' 2>/dev/null")
    end, MENU_TOOLS_UNSORTED)
    
    print("PacketPoet plugin loaded successfully")
end

-- Initialize
if gui_enabled() then
    create_menu()
end
