# BlockViewer
### Brief:
Collapse and uncollapse the code block in IDA pseudocode view.
### Install：
- Build the idasdk7.5 first.
- Build with command `make` or `build64_opt.sh`.
- Copy the `.dylib` to the plugins directory of IDA pro. Or you can use mine build from `bin` directory.
### Function:
1. If the cursor is inside a function, press hotkey “ctrl+shift+J" in IDA, you will jump to the start or end address of the function.
2. In pseudocode view, double click the right space of "{" or "}", you will collapse the block, and then double click right area to uncollapse.

##### By the way, I develop this plugin to meet the demand that view a big code block in IDA, instead of copying to another editor.The code is open source, you can clone and modify at random. Maybe there are some bugs, welcome to pull requests. 
