# Ambit agent workspace image

This is the admitted Daytona container image for Ambit agent workspaces. It
extends the pinned Daytona slim sandbox and guarantees Ambit's portable
workspace contract: `/workspace` exists and is writable by the runtime user.

Keep provider-independent runtime paths in Ambit. Provider images are
responsible for satisfying this filesystem contract before admission.
