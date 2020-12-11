import React, { useState } from "react"
import AriaModal from "react-aria-modal"
import styled from "styled-components"
import CreateTokenForm from "./createTokenForm"

const StyledModal = styled.div`
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background: white;
  foreground: black;
  width: 600px;
  max-width: 100%;
`

function NewToken({ token, onAccept = f => f }) {
  return (
    <>
      <p>
        Your new token is:
      </p>
      <p><code>{token}</code></p>
      <p>
        Save this token now.  After closing this notification, you{" "}
        <strong>will not be able to see this token again.</strong>{" "}
        If lost, you will need to delete the token and create a new one.
      </p>
      <button type="submit" id="token-accept" onClick={onAccept}>
        Okay
      </button>
    </>
  )
}

export default function CreateTokenButton({ onCreateToken = async f => f }) {
  const [formActive, setFormActive] = useState(false)
  const [newToken, setNewToken] = useState("")

  const activateFormModal = () => { setFormActive(true) }
  const deactivateFormModal = () => { setFormActive(false) }
  const deactivateTokenModal = () => { setNewToken("") }
  const getApplicationNode = () => { document.getElementById("application") }

  const createToken = async (values) => {
    await onCreateToken(values, setNewToken)
    deactivateFormModal()
  }

  const modal = (
    newToken
    ? <AriaModal
           titleText="New token"
           alert={true}
           onExit={deactivateTokenModal}
           getApplicationNode={getApplicationNode}
         >
           <StyledModal>
             <NewToken token={newToken} onAccept={deactivateTokenModal} />
           </StyledModal>
         </AriaModal>
    : (formActive
      ? <AriaModal
          titleText="Create token"
          initialFocus="#token-accept"
          onExit={deactivateFormModal}
          getApplicationNode={getApplicationNode}
        >
          <StyledModal>
            <CreateTokenForm
              onCreateToken={createToken}
              onCancel={deactivateFormModal}
            />
          </StyledModal>
        </AriaModal>
    : false)
  )

  return (
    <>
      <button onClick={activateFormModal}>Create Token</button>
      {modal}
    </>
  )
}
