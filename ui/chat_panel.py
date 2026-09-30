"""Chat UI boundary.

UI code should call a controller/executor and must not execute network commands.
"""


class ChatPanel:
    def __init__(self, controller):
        self.controller = controller

    def submit(self, text: str):
        return self.controller.handle_user_message(text)
