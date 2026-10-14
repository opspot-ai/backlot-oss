__all__ = ["Backlot", "Computer"]


def __getattr__(name):
    if name in __all__:
        from .client import Backlot, Computer

        return {"Backlot": Backlot, "Computer": Computer}[name]
    raise AttributeError(name)
