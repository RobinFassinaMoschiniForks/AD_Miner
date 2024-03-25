from ad_miner.sources.modules.controls import Control
from ad_miner.sources.modules.controls import register_control


@register_control
class my_control_class_name(Control):  # TODO change the class name
    "Docstring of my control"  # TODO small documentation here

    def __init__(self, arguments, requests_results) -> None:
        super().__init__(arguments, requests_results)

        # TODO define this to "azure" or "on_premise" accordingly
        self.azure_or_onprem = ""

        # TODO add the control key. This string should be uniq and will be used
        # by the code and written to the data json.
        # Do NOT change existing control_key, as it will break evolution with older ad miner versions
        self.control_key = "users_shadow_credentials_to_non_admins"

        # self.description = "test control description" #TODO maybe ?

    def run(self):
        # TODO The code for the analysis goes here

        # TODO define the metric of your control
        # it will be stored in the data json
        self.data = -1

        # TODO define the sentence that will be displayed in the 'smolcard' view and in the center of the mainpage
        self.name_description = f"... {12} ...."

    def get_rating(self) -> int:
        # TODO define the rating function.
        # You can use common rating functions define in ad_miner.sources.modules.common_analysis like presenceof, percentage_superior, etc.
        # -1 = grey, 1 = red, 2 = orange, 3 = yellow, 4 =green, 5 = green,
        return -1
