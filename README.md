# tadoauth

A Telegraf plugin to authenticate and re-authenticate to the Tado website. The routine receives a "bearer"-token and stores in a file. regular HTTP inputs can then use the bearer token for authentication. A background loop is started to re-authenticate within the refresh-interval.
It is currently implemented as an Input plugin, but it does not actually collect any input.
# Installation
The plugin runs under the shim-module
