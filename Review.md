| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure	[1]						|Nhi Truong|06/24/2020|*|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|Nhi Truong|06/24/2020|*|
||InSpec syntax checker|Nhi Truong|06/24/2020||*|
||Local commands focused on target not the runner [2]|*Nhi Truong|*06/24/2020|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|Nhi Truong|06/24/2020|*|
||Control robustness (can the control be improved to make it less brittle - not necessarily a blocker on initial releases)|Nhi Truong|06/24/2020|*|
||Descriptive output for findings details (review JSON for findings information that may be confusing to SCA like NilCLass, etc.)|Nhi Truong|06/24/2020|*|
||Documentation quality (i.e. README)<br> novice level instructions including prerequisites|Nhi Truong|06/24/2020|*|
||Consistency across other profile conventions |Nhi Truong|06/24/2020|*|
||Spelling, grammar,linting (e.g., rubocop, etc.)|Nhi Truong|06/24/2020|*|
||Removing debugging documentation and code|Nhi Truong|06/24/2020|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges (e.g., code fails to reach a describe statement for every control. inspec check can do this. It will say no defined tests)|Nhi Truong|06/24/2020|*|
||Slowing the target (e.g. filling up disk, CPU spikes)|Nhi Truong|06/24/2020|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Nhi Truong|06/24/2020|*|
||Check for “stuck” situations (e.g., profile goes on forever due to infinite loop, very large data sets, etc.)|Nhi Truong|06/24/2020|*|

[1] https://www.inspec.io/docs/reference/profiles/

[2] https://www.inspec.io/docs/reference/style/ (see "Avoid Shelling Out")

Another tip is to cat all the controls into a single file so you don't have to open every individaul file and try to keep track of where you are and which one is next.


*** A completion date is entered in a row when all non-enhancement issues are resolved for that review row.
