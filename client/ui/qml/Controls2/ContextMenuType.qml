import QtQuick
import QtQuick.Controls

Menu {
    property var textObj

    // popupType: Popup.Native needs Qt 6.5+ Controls; Qt 6.4 (e.g. Ubuntu 24.04) has no Menu.popupType.

    MenuItem {
        text: qsTr("C&ut")
        enabled: textObj ? Boolean(textObj.selectedText) : false
        onTriggered: {
            if (textObj)
                textObj.cut()
        }
    }
    MenuItem {
        text: qsTr("&Copy")
        enabled: textObj ? Boolean(textObj.selectedText) : false
        onTriggered: {
            if (textObj)
                textObj.copy()
        }
    }
    MenuItem {
        text: qsTr("&Paste")
        // Fix calling paste from clipboard when launching app on android
        enabled: Qt.platform.os === "android" ? true : (textObj ? Boolean(textObj.canPaste) : false)
        onTriggered: {
            if (textObj)
                textObj.paste()
        }
    }

    MenuItem {
        text: qsTr("&SelectAll")
        enabled: textObj ? (textObj.length > 0) : false
        onTriggered: {
            if (textObj)
                textObj.selectAll()
        }
    }
}
