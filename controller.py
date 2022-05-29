'''
Woodchipper v0.2 - Copyright 2022 James Slaughter,
This file is part of Woodchipper v0.2.

Woodchipper v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Woodchipper v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Woodchipper v0.2.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
controller.py - This file is responsible for keeping global settings available through class properties
'''

#python imports
import imp
import sys

'''
controller
Class: This class is is responsible for keeping global settings available through class properties
'''
class controller:
    '''
    Constructor
    '''
    def __init__(self):

        self.debug = False
        self.manifest = ''
        self.dir = ''
        self.output = ''
        self.manifestdata = ''
        

