class ConstantError(Exception):
    def __init__(self, message="Cannot change constant"):
        self.message = message
        super().__init__(self.message)
    def __str__(self):
        return self.message

class Constants(object):

    """
    Create objects with read-only (constant) attributes.
    Example:
        Nums = Constants(ONE=1, PI=3.14159, DefaultWidth=100.0)
        print 10 + Nums.PI
        Nums.PI = 22 # ConstantError
    """

    def __init__(self, *args, **kwargs):
        self._d = dict(*args, **kwargs)
    def __iter__(self):
        return iter(self._d)
    def __len__(self):
        return len(self._d)
    def __getattr__(self, name):
        return self._d[name]
    def __setattr__(self, name, value):
        if not (name[0] == "_"):
            raise ConstantError
        else:
            super(Constants, self).__setattr__(name, value)