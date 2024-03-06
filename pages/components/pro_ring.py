from flet import *

class ProRing(UserControl):
    def __init__(self,width=0):
        super().__init__()
        self.__width = width
        
    
    def build(self):
        container = Container(
                padding=50,
    
                content=Column(
                    
                    horizontal_alignment=CrossAxisAlignment.CENTER,
                    alignment=MainAxisAlignment.CENTER,
                    controls=[Row(
                            alignment=MainAxisAlignment.CENTER,
                            controls=[ProgressRing(animate_size=200)]
                        )
                    ]
                )
            )
        if self.__width != 0:
            container.width=self.__width
        return container