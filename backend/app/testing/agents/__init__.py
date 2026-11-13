"""RedPilot agent layer (A-roster) -- real Agent objects over bounded capabilities.

See base.py for the Agent/AgentReport contract. Concrete agents live in the role
modules (recon.py, attack.py, proof.py, learning.py, planning.py, orchestration.py)
and the domain packs (domain_packs.py); `registry.py` assembles them into one roster.
"""
