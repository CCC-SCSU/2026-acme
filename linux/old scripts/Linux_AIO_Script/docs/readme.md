# Linux System Maintenance Utility

## What This Does
A modular system administration toolkit. Does stuff. Important stuff. Probably.

## Prerequisites
- Root access (shocking, I know)
- A Linux system that you presumably want to keep running
- The ability to read prompts and make decisions

## Usage
For those who prefer graphical menus over reading documentation:
bash
sudo ./main.sh

Follow the on-screen prompts. They're there for a reason.

For those who insist on doing things manually:
bash
sudo ./main.sh --phase1    # Does the first thing
sudo ./main.sh --phase2    # Does the second thing  
sudo ./main.sh --phase3    # Does the third thing
sudo ./main.sh --all       # Does all the things

## Phase 1: Initial Configuration
Handles immediate system requirements. Takes 2-5 minutes if you know what you're doing.

## Phase 2: Comprehensive Configuration  
Handles everything else. Budget 15-25 minutes. Possibly more if things are particularly interesting.

## Phase 3: Optional Enhancements
Additional components. Install what you need. Skip what you don't.

## Structure
.
├── main.sh                      # Start here
├── phase1_main.sh               # Or here if you're feeling adventurous
├── phase2_main.sh               # Or here if you really know what you're doing
├── phase3_main.sh               # Or here if you're just showing off
├── lib/                         # Shared functionality
├── modules/                     # The actual work happens here
├── monitors/                    # Watches things
├── enum/                        # Lists things
├── utilities/                   # Does things
└── config/                      # Configures things

## Documentation
- Logs go in `/var/log/aio_hardening/`
- Monitoring output goes in `/var/log/redflags/`
- Everything else is where you'd expect it to be

## Troubleshooting
1. Read the error message
2. Check the logs (see above)
3. Try again
4. Check the logs again
5. Consider whether you actually need that feature

## Support
This is a tool. You use tools. Tools don't come with tech support.
You break it, you fix it.
**We're just a pack of dogs running around howling chaotically, what support could we even give?**

## License
Use it. Don't abuse it. Don't blame us if you do.

## Credits
Created by students who care about system security.
Maintained by people who care about their competition scores.