from elem.core import ElemResource

class ElemResourceContainer(ElemResource):
    def __init__(self, location, tlsverify=False):
        super(ElemResourceContainer, self).__init__(location, tlsverify=tlsverify)