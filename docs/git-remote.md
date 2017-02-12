Syncrypt as a git remote
========================



First, setup your git vault. Syncrypt allows you to have unlimited vaults, so
you can create a vault for each repository you want to store.

    $ syncrypt create-git

    Create a new git vault: syncrypt://14719287129831723981273

Now you can simply push to this git remote:

    $ git push syncrypt://14719287129831723981273

For more convenience, you can add the syncrypt remote as git remote:

    $ git remote

You can clone it as well:

    $ git clone syncrypt://14719287129831723981273

