Here's a few things I need you to go over, as well as add to the agents file and your memory
1: Are any warnings or errors being suppressed? This is an illegal operation, warnings and errors need to be treated as valid, and fixed, not hidden
3: Does every file in the repo pass the end-user/contributor test? Each committed file must be something an end user needs to build the project, or a human contributor needs to make a contribution. Files that fail this test belong in .gitignore.
4: Do any commits reference an LLM beyond attributing a specific finding? Commit messages describe the code change and the developer is the author. The only permitted LLM reference is crediting a specific discovery: "finding surfaced by review from (LLM name)".
4: do any commits reference claude code, chatGPT codex, or any other LLM? If so, those commits need to be amended, folded into other commits, etc
5: Do any functions, systems, or code have multiple implementations, unused implementation, multiple typedefs, unnecessary imports, etc? We reuse and improve existing code whenever possible
6: Are any functions, systems, or things in the specification currently unimplemented? This needs to be corrected
7: Are there any potential vulnerabilities in the code or the spec? Any found vulnerabilities must be raised to the appropriate party. AI Agents raise findings and proposed solutions to the user, who determines how to proceed, but must ALSO provide one or more proposed solutions or references to reinforce the finding.
8: Does code follow the project conventions? This project uses snake_case
9: Does the code properly error-handle? It needs to
10: Is the code implemented in a way that is simple and easy to read? It needs to be
11. Is the code sufficiently commented? On average, every line of code should have two lines of comments. This commentspace exists to maximize understanding — use it liberally to explain intent, context, and reasoning, not to fill a quota.

These are the MINIMUM standards the code must adhere to to be "compliant code". Adherence to these standards, and adherence to the specification, are 2 out of the 3 requirements for "compliant code". The third is accuracy, and that is determined through human review.
Please action this information, and add this information to our standard code-review set. 