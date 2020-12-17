import PropTypes from 'prop-types';
import React from 'react';
import { Formik, Form, Field, ErrorMessage } from 'formik';

export default function CreateTokenForm({ scopes, onCreateToken, onCancel }) {
  return (
    <Formik
      initialValues={{ name: '', scopes: [], expires: '' }}
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
          <div id="create-token-scopes-label">Scopes:</div>{' '}
          <div
            role="group"
            id="create-token-scopes"
            aria-labelledby="create-token-scopes-label"
          >
            {scopes.map(({ name, description }) => (
              <>
                <label>
                  <Field type="checkbox" name="scopes" value={name} />
                  <bold className="qa-scope-name">{name}</bold>: {description}
                </label>
                <br />
              </>
            ))}
          </div>
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
CreateTokenForm.propTypes = {
  scopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    })
  ),
  onCreateToken: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
};
