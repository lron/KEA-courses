## FOR loop in Bash

This script is meant to help with the following exercise:

### GREP as a code review tool

1. Make sure you have a Github account (create one if you don't) and that you also have git running on your computer ([install it](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) if you don't). 
2. [Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the Github repository [Let's be bad guys](https://github.com/mpirnat/lets-be-bad-guys) so as to have a copy of the original repository in your own Github account. Set the visibility of the new repository as public, to be able to use the free accounts of some of the static code analysis tools that we'll use in upcoming exercises.
3. Create a new directory in your machine and [clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) your forked repository so as to have a local copy of the repository files.
4. Do a brainstorming in groups and try to find a list of keywords or expressions that would be interesting to include in our grep search, potentially indicating a bug or vulnerability in the code.
Look at grep documentation and come up with the command we’ll need to use to find each of the above words. You might find useful to have a look at the [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/), especially the section devoted to *code crawling*.
5. Write a script in, for instance, bash, which uses the list (array) from section 4 and calls iteratively (in a loop) the command from section 5 for each keyword in the array. Give it execution permissions (*chmod +x*) and run it against the local repository to find patterns in the code which could be indicating security vulnerabilities.
6. What security issues do you find using this technique? In which cases it could be useful to use?

