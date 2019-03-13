import re

class InvalidExample(Exception):
    def __init__(self, name, pattern, example):
        message = "For score {0}, example {1} does not match pattern {2}.".format(name, example, pattern)
        super(InvalidExample, self).__init__(message)

class Score(object):
    def __init__(self, name, pattern, example=None):
        self.name = name
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.example = example
        if self.example and not self.is_valid(self.example):
            raise InvalidExample(self.name, self.pattern, self.example)

    def is_valid(self, score_string):
        if not isinstance(score_string, str):
            score_string = str(score_string)
        matches = re.search(self.regex, score_string)
        if not matches:
            return False
        return True

    def __str__(self):
        return "{0},{1},{2}".format(self.name, self.pattern, self.example or '')

    def __iter__(self):
        score_dict = dict()
        score_dict[self.name] = dict(pattern=self.pattern, example=self.example or '')
        return iter(score_dict)

