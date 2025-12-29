```
# Build Process Explanation

**Table of Contents**
- [The Full Build Process: `build.sh`](#the-full-build-process-buildsh)
- [How to Perform an Incremental Build](#how-to-perform-an-incremental-build)
  - [First Time Only: Initial Setup](#first-time-only-initial-setup)
  - [Scenario 1: If you only make changes in the `demo` folder](#scenario-1-if-you-only-make-changes-in-the-demo-folder)
  - [Scenario 2: If you make changes in the `demo` folder, including the `CMakeLists.txt` file](#scenario-2-if-you-make-changes-in-the-demo-folder-including-the-cmakeliststxt-file)

---

## The Full Build Process: `build.sh`

Your `build.sh` script is designed for a **full, clean build** every time it runs. It is not set up for incremental builds. Here’s a breakdown of its actions:

1.  **Deletes Previous Builds**: It starts by completely removing the `base_build/` and `build/` directories (`rm -rf ...`). This ensures that every build starts from a clean slate, with no old files left over.
2.  **Builds the `base` Dependency**: It compiles and installs a core dependency located in the `base/` directory into the `base_build/install/` folder.
3.  **Builds the Main Project**: It then configures and compiles the main project (including your `demo/` directory), linking against the `base` dependency it just built.

Because `build.sh` always starts by deleting the build directories, it cannot perform an incremental build.

---

## How to Perform an Incremental Build

To save time and only recompile what has changed, you should **not** use the `build.sh` script after your first build. Instead, follow these steps.

### First Time Only: Initial Setup

1.  Run the build script to create the initial build directories and compile everything.
    ==!!==bash
    ./build.sh
    ==!!==

### Scenario 1: If you only make changes in the `demo` folder (e.g., editing `.cpp` or `.h` files)

After the initial setup, if you only modify source code, the process is much faster:

1.  **Navigate into the `build` directory**:
    ==!!==bash
    cd build/
    ==!!==
2.  **Run `make`**:
    ==!!==bash
    make
    ==!!==
    `make` will automatically detect which source files have changed and only recompile them and their dependencies.

### Scenario 2: If you make changes in the `demo` folder, including the `CMakeLists.txt` file

If you edit `demo/CMakeLists.txt` (for instance, to add a new source file), you need to tell CMake to update the build configuration before compiling.

1.  **Navigate into the `build` directory**:
    ==!!==bash
    cd build/
    ==!!==
2.  **Run `cmake` to update the configuration**:
    ==!!==bash
    cmake .
    ==!!==
3.  **Run `make` to compile the changes**:
    ==!!==bash
    make
    ==!!==
This ensures that the build system is aware of your changes before it starts compiling.
```
