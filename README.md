# HookMap

Finds out which SKSE plugins patch the same parts of Skyrim, and helps you find the ones that crash together.

Two parts:

1. **HookMap.dll** (in game, an SKSE plugin). Once the game is at the main menu it compares the game's code and pointers with what the game shipped with and writes a report: which DLL patched which function. Two DLLs that patch the same function are listed as an overlap.
2. **HookMap.App.exe** (offline, a Windows program). Reads those reports, your crash logs and your Mod Organizer 2 profile, ranks the SKSE mods by how suspicious they are for a crash, and runs a bisect: it makes a copy of your profile with some SKSE mods switched off, you play, you answer "crashed" or "no crash", and it narrows the list down to the smallest set of mods that still crashes together.

Nothing is changed in your own profile, your mod folders or the game. The bisect writes only a separate test profile that HookMap makes (it refuses to touch a profile it did not make).

## Use

1. Unzip the program anywhere. Needs the .NET 10 Desktop Runtime (x64).
2. Run `HookMap.App.exe`. Pick your MO2 folder (the one with `ModOrganizer.ini`) and press **Read SKSE mods**.
3. Press **Add HookMap plugin to MO2**. It creates a mod called "HookMap" in your mods folder. In MO2 press F5 and tick it.
4. Start the game, go to the main menu, then load a save (the second snapshot catches plugins that hook late). Quit the game.
5. **Hook map** tab: press **Load reports from MO2**. The right side lists every function patched by more than one DLL, with the bytes, where each jump goes, and which DLL owns it.
6. **Crash log** tab: pick a crash log. With a report loaded, it shows which functions on the crash's call stack other DLLs have patched, and ranks the DLLs.
7. **Bisect** tab: press **Create plan**, then follow the steps. Each step says which SKSE mods are on and off. Prepare the test profile, start MO2 with that profile, do the same test every time, and answer.

## What the report means

- **Two DLLs patch one function**: normal when both call on to the original code. It becomes interesting when the crash is inside or just below that function.
- **Late**: the patch was not there at the main menu; the plugin installed it later.
- **The exe on disk is copy-protected** (Steam): HookMap then finds patches by pattern (jumps and calls that leave the game for another DLL's memory, pointers that no longer point into the game). Direct byte edits (changing a constant) are only found when the exe on disk can be compared.
- A patch whose jump could not be followed to a DLL is shown with owner `?`.

## Build

```powershell
.\build.ps1        # plugin (needs Visual Studio's C++ tools and CMake) + the plugin self-test
.\package.ps1      # release\HookMap-<v>.zip and release\HookMap Plugin-<v>.zip
dotnet test offline\tests\HookMap.Core.Tests -c Release
```

The plugin has no dependencies (no CommonLib, no vcpkg) and uses no game structures, so one DLL covers Skyrim SE 1.5.97, AE and newer, and VR. The self-test (`plugin\build\Release\hookmap_selftest.exe`) patches its own code the way plugins do and checks the scan names the right DLLs.

Command line: `HookMap.exe mods|report|crash|plan ...` (run it without arguments for the list).

## Limits

- It shows where plugins patch the game and what a crash's call stack contains. It cannot say that two patches fight each other: that is for the bisect.
- The bisect needs a crash you can repeat in a few minutes.
- Mods that carry a plugin other mods need (patches), and a patch that depends on many SKSE mods at once, stay on or go off together; the plan says which.

## License

GPL-3.0-only. See LICENSE.txt.
