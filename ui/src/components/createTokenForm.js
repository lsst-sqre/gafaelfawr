import React from 'react';
import { Formik, Form, Field, ErrorMessage } from 'formik';

export default function CreateTokenForm({
  onCreateToken = async (f) => f,
  onCancel = (f) => f,
}) {
  return (
    <Formik
      initialValues={{ name: '', scopes: '', expires: '' }}
      validate={(values) => {
        const errors = {};
        if (!values.name) {
          errors.name = 'Required';
        } else if (values.name.length > 64) {
          errors.name = 'Must be 64 characters or less';
        }
        return errors;
      }}
      onSubmit={async (values, { setSubmitting }) => {
        await onCreateToken(values);
        setSubmitting(false);
      }}
    >
      {({ isSubmitting }) => (
        <Form>
          <label htmlFor="create-token-name">Name:</label>{' '}
          <Field
            id="create-token-name"
            name="name"
            type="text"
            maxlength="64"
            placeholder="token name"
          />
          <ErrorMessage name="name" component="div" />
          <br />
          <label htmlFor="create-token-scopes">Scopes:</label>{' '}
          <Field
            id="create-token-scopes"
            name="scopes"
            type="text"
            placeholder="read:tap,read:workspace"
          />
          <ErrorMessage name="scopes" component="div" />
          <br />
          <label htmlFor="create-token-expires">Expires:</label>{' '}
          <Field
            id="create-token-expires"
            name="expires"
            type="text"
            placeholder="1607471088"
          />
          <ErrorMessage name="expires" component="div" />
          <br />
          <button type="submit" disabled={isSubmitting}>
            Create
          </button>
          <button type="button" disabled={isSubmitting} onClick={onCancel}>
            Cancel
          </button>
        </Form>
      )}
    </Formik>
  );
}
